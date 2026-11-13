"""
Creates a learning switch that implements the most basic possible
DoS rule. If an external host sends packets to a server faster than a given
threshold, it blocks the (src, dst) pair, permanently or for BLOCK_SECONDS.
"""

import ipaddress
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

# Currently hardcoded network range for servers
SERVER_NET = ipaddress.ip_network("10.0.0.0/24")
# Also hardcoded packet per second threshold
THRESHOLD_PPS = 200
# Poll once per second
POLL_SECONDS = 1.0
# Ignore samples taken closer together than this (too noisy)
MIN_SAMPLE_SECONDS = POLL_SECONDS / 2
# Forget counters for flows that haven't shown up in a stats reply for this amount of time
STALE_SECONDS = 5 * POLL_SECONDS
# If BLOCK_SECONDS is 0, the block is permanent
BLOCK_SECONDS = 0

FORWARD_PRIORITY = 10
BLOCK_PRIORITY = 100


class DumbSwitch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}   # dpid: {mac: port}
        self.datapaths = {}     # dpid: dp
        # (dpid, src, dst): (packet_count, flow_duration, seen_at)
        self.last_seen = {}
        self.blocked = set()    # dpid, src, dst
        self.monitor_thread = hub.spawn(self._monitor)

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
            self._add_flow(dp, FORWARD_PRIORITY, match, actions, idle_timeout=10)

        # Forward the packet
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

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
            hub.sleep(POLL_SECONDS)

    def _prune_stale(self):
        """Drop counters for flows the switch no longer reports (e.g. idled out)."""
        cutoff = time.monotonic() - STALE_SECONDS
        for key in [k for k, (_, _, seen_at) in self.last_seen.items() if seen_at < cutoff]:
            del self.last_seen[key]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # type: ignore
    def flow_stats_handler(self, ev):
        """Handle receiving stats."""
        dp = ev.msg.datapath
        now = time.monotonic()

        for stat in ev.msg.body:
            if stat.priority != FORWARD_PRIORITY:
                continue
            src, dst = stat.match.get("ipv4_src"), stat.match.get("ipv4_dst")
            if src is None or dst is None:
                continue
            # Ignore server-to-external and server-to-server
            if ipaddress.ip_address(dst) not in SERVER_NET or ipaddress.ip_address(src) in SERVER_NET:
                continue

            key = (dp.id, src, dst)
            if key in self.blocked:
                # Start from a fresh baseline once the block is lifted
                self.last_seen.pop(key, None)
                continue

            # Use the switch's own clock for the flow, not when the reply reached us
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            prev = self.last_seen.get(key)

            if prev is None:
                self.last_seen[key] = (stat.packet_count, duration, now)
                continue

            prev_count, prev_duration, _ = prev
            elapsed = duration - prev_duration
            delta = stat.packet_count - prev_count

            # Counter or duration went backwards: the flow was replaced, rebaseline
            if elapsed < 0 or delta < 0:
                self.last_seen[key] = (stat.packet_count, duration, now)
                continue
            # Too soon after the last sample, keep the older baseline
            if elapsed < MIN_SAMPLE_SECONDS:
                continue

            self.last_seen[key] = (stat.packet_count, duration, now)
            rate = delta / elapsed

            # Block the (src, dst) pair if the rate exceeds the stated threshold
            if rate > THRESHOLD_PPS:
                self._block(dp, src, dst, rate)

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

    def _block(self, dp, src, dst, rate):
        """Blocks a (src, dst) pair."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src, ipv4_dst=dst)
        # Ask for a FlowRemoved message so we know when a temporary block expires
        self._add_flow(dp, BLOCK_PRIORITY, match, [],
                       hard_timeout=BLOCK_SECONDS, flags=ofp.OFPFF_SEND_FLOW_REM)
        self.blocked.add((dp.id, src, dst))
        self.last_seen.pop((dp.id, src, dst), None)
        self.logger.warning(f"BLOCKED: {src} -> {dst} at {rate:.0f} pps")
