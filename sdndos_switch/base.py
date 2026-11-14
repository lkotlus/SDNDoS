"""
Base switch that all other switches are built from. Handles all the nerd stuff that you
don't want to reimplement. Results are handed to any Detector or Mitigator, chosen by
the subclass.
"""

import time
from itertools import count

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.lib.packet import ether_types, ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3

from sdndos_switch.actions import Actions
from sdndos_switch.detection import Detector
from sdndos_switch.mitigation import Mitigator
from sdndos_switch.models import Alert, FlowSample, MitigationRule, PollWindow

# Poll once per second
POLL_SECONDS = 1.0
# If samples are taken closer together than this given time (measured by the switch),
# they ought to be ignored.
MIN_SAMPLE_SECONDS = POLL_SECONDS / 2
# If a flow hasn't been seen in stats polling in this amount of time, forget the
# counters for it.
STALE_SECONDS = 5 * POLL_SECONDS
# Forwarding flows expire after this many seconds without traffic
FORWARD_IDLE_SECONDS = 10
# A pair counts as active if it carried traffic within this many seconds
ACTIVE_SECONDS = 3 * POLL_SECONDS
# OpenFlow timeouts are 16 bit
MAX_TIMEOUT_SECONDS = 65535

# Table 0 holds mitigation rules and passes everything else on to table 1,
# which does normal learning-switch forwarding. Rate limited traffic still reaches its
# forwarding flow, so detectors keep seeing the rate after the limit.
MITIGATION_TABLE = 0
FORWARD_TABLE = 1

FORWARD_PRIORITY = 10
BLOCK_PRIORITY = 100
# Other mitigation rule priorities in table 0, the highest matching rule wins
SOURCE_LIMIT_PRIORITY = 60
ALLOW_PRIORITY = 50
VICTIM_LIMIT_PRIORITY = 40


class BaseSwitch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}   # dpid: {mac: port}
        self.datapaths = {}     # dpid: dp
        # (dpid, src, dst): (packet_count, byte_count, flow_duration, seen_at)
        self.last_seen = {}
        self.first_seen = {}    # (dpid, src, dst): when the pair was first sampled
        self.last_active = {}   # (dpid, src, dst): when the pair last carried traffic
        self.blocked: set[tuple[int, str, str]] = set()    # dpid, src, dst
        self._pending_samples = {}  # dpid: [FlowSample] for a stats reply still arriving

        self.rules: dict[int, MitigationRule] = {}  # cookie: installed mitigation rule
        self._rule_index = {}   # (kind, dpid, src, dst): cookie
        self._cookies = count(1)
        self._meter_ids = {}    # dpid: meter id counter
        self._table_miss_meter = {}  # dpid: meter id on the table-miss flow

        self.detector = self.make_detector()
        self.mitigator = self.make_mitigator()
        self.actions = Actions(self)
        self.logger.info(f"Detector: {self.detector.name}, mitigator: {self.mitigator.name}")

        self.monitor_thread = hub.spawn(self._monitor)

    def make_detector(self) -> Detector:
        """Override to choose the detection strategy."""
        raise NotImplementedError

    def make_mitigator(self) -> Mitigator:
        """Override to choose the mitigation strategy."""
        raise NotImplementedError

    def _dispatch(self, alerts: list[Alert]):
        """Hand every alert to the mitigator."""
        for alert in alerts:
            self.mitigator.on_alert(alert, self.actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # type: ignore
    def switch_features_handler(self, ev):
        """
        Install the table-miss flow, which sends unmatched packets to the controller,
        and table 0's default flow, which passes anything not mitigated on to forwarding
        """
        dp = ev.msg.datapath
        self.logger.info(f"Switch connected: {dp.id}")
        parser, ofp = dp.ofproto_parser, dp.ofproto
        self._add_flow(dp, MITIGATION_TABLE, 0, parser.OFPMatch(), goto=FORWARD_TABLE)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, FORWARD_TABLE, 0, parser.OFPMatch(), actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])  # type: ignore
    def state_change_handler(self, ev):
        """Handle OpenFlow switch connection/disconnection."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            is_new = dp.id not in self.datapaths
            self.datapaths[dp.id] = dp
            if is_new:
                self.mitigator.on_switch_connected(dp.id, self.actions)
        else:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # type: ignore
    def packet_in_handler(self, ev):
        """Handle inbound packets."""
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        # No ethernet header, no LLDP frame, no service (don't forward chatter)
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP: #type: ignore
            return

        # Set up our mac address to port pairing
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port #type: ignore
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD) #type: ignore
        actions = [parser.OFPActionOutput(out_port)]

        # If the destination is known, set up a per-IP-pair flow
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None and out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip.src, ipv4_dst=ip.dst, #type: ignore
            )
            self._add_flow(dp, FORWARD_TABLE, FORWARD_PRIORITY, match, actions,
                           idle_timeout=FORWARD_IDLE_SECONDS)

        # Forward the packet
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

        # Let the detector see the packet after it has been forwarded
        self._dispatch(self.detector.on_packet_in(dp.id, pkt, time.monotonic()))

    def _add_flow(self, dp, table_id, priority, match, actions=None, goto=None, meter_id=None,
                  idle_timeout=0, hard_timeout=0, flags=0, cookie=0):
        """Add a flow, no action means drop."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER))
        if actions:
            inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
        if goto is not None:
            inst.append(parser.OFPInstructionGotoTable(goto))
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=table_id, cookie=cookie, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags))

    def _add_meter(self, dp, pps, burst=None) -> int:
        """Create a meter that drops packets above pps packets per second."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        if int(pps) < 1:
            raise ValueError(f"Meter rate must be at least 1 pps, got {pps}")
        meter_id = next(self._meter_ids.setdefault(dp.id, count(1)))
        flags = ofp.OFPMF_PKTPS | (ofp.OFPMF_BURST if burst else 0)
        bands = [parser.OFPMeterBandDrop(rate=int(pps), burst_size=int(burst or 0))]
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_ADD, flags=flags, meter_id=meter_id, bands=bands))
        return meter_id

    def _delete_meter(self, dp, meter_id):
        """Remove a meter that is no longer used by any flow."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_DELETE, flags=0, meter_id=meter_id, bands=[]))

    def _monitor(self):
        """Periodically get stats."""
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            self._prune_stale()
            self.mitigator.on_tick(time.monotonic(), self.actions)
            hub.sleep(POLL_SECONDS)

    def _prune_stale(self):
        """Drop counters for flows the switch no longer reports (e.g. idled out)."""
        cutoff = time.monotonic() - STALE_SECONDS
        for key in [k for k, (*_, seen_at) in self.last_seen.items() if seen_at < cutoff]:
            del self.last_seen[key]
            self.first_seen.pop(key, None)
            self.last_active.pop(key, None)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # type: ignore
    def flow_stats_handler(self, ev):
        """Handle receiving stats."""
        msg = ev.msg
        dp = msg.datapath
        now = time.monotonic()

        pending = self._pending_samples.setdefault(dp.id, [])
        for stat in msg.body:
            sample = self._sample(dp.id, stat, now)
            if sample is not None:
                pending.append(sample)

        # Large flow tables are split over several replies, wait for the last one
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return

        window = PollWindow(
            dpid=dp.id,
            time=now,
            samples=self._pending_samples.pop(dp.id),
            blocked=frozenset((src, dst) for (dpid, src, dst) in self.blocked if dpid == dp.id),
        )
        self._dispatch(self.detector.on_poll(window))

    def _sample(self, dpid, stat, now) -> FlowSample | None:
        """
        Turn one forwarding flow's stats into a sample of the traffic since its
        last usable sample. Returns None while there's no baseline to compare against.
        """
        if stat.table_id != FORWARD_TABLE or stat.priority != FORWARD_PRIORITY:
            return None
        src, dst = stat.match.get("ipv4_src"), stat.match.get("ipv4_dst")
        if src is None or dst is None:
            return None

        key = (dpid, src, dst)
        if key in self.blocked:
            # Start from a fresh baseline once the block is lifted
            self.last_seen.pop(key, None)
            self.first_seen.pop(key, None)
            self.last_active.pop(key, None)
            return None

        # Use the switch's own clock for the flow, not when the reply reached us
        duration = stat.duration_sec + stat.duration_nsec / 1e9
        current = (stat.packet_count, stat.byte_count, duration, now)
        prev = self.last_seen.get(key)

        if prev is None:
            self.last_seen[key] = current
            self.first_seen.setdefault(key, now)
            return None

        prev_count, prev_bytes, prev_duration, _ = prev
        elapsed = duration - prev_duration
        delta = stat.packet_count - prev_count

        # Counter or duration went backwards: the flow was replaced, rebaseline
        if elapsed < 0 or delta < 0:
            self.last_seen[key] = current
            return None
        # Too soon after the last sample, keep the older baseline
        if elapsed < MIN_SAMPLE_SECONDS:
            return None

        self.last_seen[key] = current
        if delta > 0:
            self.last_active[key] = now
        return FlowSample(src, dst, delta, max(stat.byte_count - prev_bytes, 0), elapsed)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)  # type: ignore
    def flow_removed_handler(self, ev):
        """
        Covers every mitigation rule.
        """
        msg = ev.msg
        rule = self.rules.pop(msg.cookie, None)
        if rule is None:
            return
        self._rule_index.pop((rule.kind, rule.dpid, rule.src, rule.dst), None)
        if rule.meter_id is not None:
            self._delete_meter(msg.datapath, rule.meter_id)

        if rule.kind == "block" and rule.src is not None:
            self.blocked.discard((rule.dpid, rule.src, rule.dst))
            self.logger.warning(f"UNBLOCKED: {rule.src} -> {rule.dst}")
        else:
            self.logger.warning(f"REMOVED {rule.kind.upper()}: {rule.src or '*'} -> {rule.dst}")
        self.mitigator.on_rule_removed(rule, self.actions)

    def _install_rule(self, kind, dpid, src, dst, priority, seconds,
                      goto=None, pps=None, burst=None) -> bool:
        """
        Install one mitigation rule in table 0 matching src -> dst (any source if src
        is None), optionally metered. Returns False if an identical rule already exists
        or the switch isn't connected.
        """
        key = (kind, dpid, src, dst)
        dp = self.datapaths.get(dpid)
        if dp is None or key in self._rule_index:
            return False
        if not 0 <= int(seconds) <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"Timeout must be between 0 and {MAX_TIMEOUT_SECONDS}s, got {seconds}")

        parser, ofp = dp.ofproto_parser, dp.ofproto
        fields = {"eth_type": ether_types.ETH_TYPE_IP, "ipv4_dst": dst}
        if src is not None:
            fields["ipv4_src"] = src
        meter_id = self._add_meter(dp, pps, burst) if pps is not None else None
        cookie = next(self._cookies)

        # Ask for a FlowRemoved message so we know when a temporary block expires
        self._add_flow(dp, MITIGATION_TABLE, priority, parser.OFPMatch(**fields),
                       goto=goto, meter_id=meter_id, hard_timeout=int(seconds),
                       flags=ofp.OFPFF_SEND_FLOW_REM, cookie=cookie)
        self.rules[cookie] = MitigationRule(kind, dpid, src, dst, cookie, meter_id, int(seconds))
        self._rule_index[key] = cookie
        return True

    def _has_rule(self, kind, dpid, src, dst) -> bool:
        return (kind, dpid, src, dst) in self._rule_index

    def _block(self, dpid: int, src: str, dst: str, seconds: int) -> bool:
        """Blocks a (src, dst) pair."""
        if not self._install_rule("block", dpid, src, dst, BLOCK_PRIORITY, seconds):
            return False
        key = (dpid, src, dst)
        self.blocked.add(key)
        self.last_seen.pop(key, None)
        self.first_seen.pop(key, None)
        self.last_active.pop(key, None)
        return True

    def _rate_limit(self, dpid, src, dst, pps, seconds, burst) -> bool:
        """Meter src -> dst (or all traffic to dst) and pass the rest on to forwarding."""
        priority = SOURCE_LIMIT_PRIORITY if src is not None else VICTIM_LIMIT_PRIORITY
        return self._install_rule("limit", dpid, src, dst, priority, seconds,
                                  goto=FORWARD_TABLE, pps=pps, burst=burst)

    def _allow(self, dpid, src, dst, seconds) -> bool:
        """Send src -> dst straight to forwarding, above any victim-wide limit."""
        return self._install_rule("allow", dpid, src, dst, ALLOW_PRIORITY, seconds, goto=FORWARD_TABLE)

    def _limit_table_miss(self, dpid, pps, burst) -> bool:
        """Re-install the table-miss flow with a meter in front of the controller."""
        dp = self.datapaths.get(dpid)
        if dp is None:
            return False
        parser, ofp = dp.ofproto_parser, dp.ofproto
        meter_id = self._add_meter(dp, pps, burst)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, FORWARD_TABLE, 0, parser.OFPMatch(), actions, meter_id=meter_id)
        old = self._table_miss_meter.get(dpid)
        if old is not None:
            self._delete_meter(dp, old)
        self._table_miss_meter[dpid] = meter_id
        return True

    def _established_sources(self, dpid, dst, min_age) -> list[str]:
        now = time.monotonic()
        return sorted(
            src for (d, src, d_dst), first in self.first_seen.items()
            if d == dpid and d_dst == dst and now - first >= min_age
            and now - self.last_active.get((d, src, d_dst), float("-inf")) <= ACTIVE_SECONDS
        )
