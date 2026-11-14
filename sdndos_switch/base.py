"""
Base switch that all other switches are built from. Handles all the nerd stuff that you
don't want to reimplement. Results are handed to any Detector or Mitigator, chosen by
the subclass.
"""

import time

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
from sdndos_switch.models import Alert, FlowSample, PollWindow

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

FORWARD_PRIORITY = 10
BLOCK_PRIORITY = 100


class BaseSwitch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}   # dpid: {mac: port}
        self.datapaths = {}     # dpid: dp
        # (dpid, src, dst): (packet_count, byte_count, flow_duration, seen_at)
        self.last_seen = {}
        self.blocked: set[tuple[int, str, str]] = set()    # dpid, src, dst
        self._pending_samples = {}  # dpid: [FlowSample] for a stats reply still arriving

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
        Install the table-miss flow that sends unmatched packets to the controller.
        """
        dp = ev.msg.datapath
        self.logger.info(f"Switch connected: {dp.id}")
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, parser.OFPMatch(), actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])  # type: ignore
    def state_change_handler(self, ev):
        """Handle OpenFlow switch connection/disconnection."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
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
            self._add_flow(dp, FORWARD_PRIORITY, match, actions, idle_timeout=FORWARD_IDLE_SECONDS)

        # Forward the packet
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

        # Let the detector see the packet after it has been forwarded
        self._dispatch(self.detector.on_packet_in(dp.id, pkt, time.monotonic()))

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0, flags=0):
        """Add a flow, no action means drop."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags))

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
        if stat.priority != FORWARD_PRIORITY:
            return None
        src, dst = stat.match.get("ipv4_src"), stat.match.get("ipv4_dst")
        if src is None or dst is None:
            return None

        key = (dpid, src, dst)
        if key in self.blocked:
            # Start from a fresh baseline once the block is lifted
            self.last_seen.pop(key, None)
            return None

        # Use the switch's own clock for the flow, not when the reply reached us
        duration = stat.duration_sec + stat.duration_nsec / 1e9
        current = (stat.packet_count, stat.byte_count, duration, now)
        prev = self.last_seen.get(key)

        if prev is None:
            self.last_seen[key] = current
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
        return FlowSample(src, dst, delta, max(stat.byte_count - prev_bytes, 0), elapsed)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)  # type: ignore
    def flow_removed_handler(self, ev):
        """Forget a block once the switch expires its drop rule."""
        msg = ev.msg
        if msg.priority != BLOCK_PRIORITY:
            return
        src, dst = msg.match.get("ipv4_src"), msg.match.get("ipv4_dst")
        key = (msg.datapath.id, src, dst)
        if key in self.blocked:
            self.blocked.discard(key)
            self.logger.warning(f"UNBLOCKED: {src} -> {dst}")
            self.mitigator.on_block_removed(msg.datapath.id, src, dst, self.actions)

    def _block(self, dpid: int, src: str, dst: str, seconds: int) -> bool:
        """Blocks a (src, dst) pair."""
        key = (dpid, src, dst)
        dp = self.datapaths.get(dpid)
        if dp is None or key in self.blocked:
            return False
        parser, ofp = dp.ofproto_parser, dp.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src, ipv4_dst=dst)
        # Ask for a FlowRemoved message so we know when a temporary block expires
        self._add_flow(dp, BLOCK_PRIORITY, match, [],
                       hard_timeout=seconds, flags=ofp.OFPFF_SEND_FLOW_REM)
        self.blocked.add(key)
        self.last_seen.pop(key, None)
        return True
