"""
Creates a learning switch that implements the most basic possible
DoS rule. If an external host sends packets to a server faster 
than a given threshold, it permanently blocks the (src, dst) pair.
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
        self.last_seen = {}     # dpid, src, dst: packet_count, timestamp
        self.blocked = set()    # dpid, src, dst
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # type: ignore
    def switch_features_handler(self, ev):
        """Install the the top priority table that sends unmatched packets to the controller."""
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

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """Add a flow, no action means drop."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout))

    def _monitor(self):
        """Periodically get stats."""
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL_SECONDS)

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
            prev = self.last_seen.get(key)
            self.last_seen[key] = (stat.packet_count, now)
            if prev is None or key in self.blocked:
                continue

            prev_count, prev_time = prev
            # Handle restarted counter.
            delta = stat.packet_count - prev_count if stat.packet_count >= prev_count else stat.packet_count
            rate = delta / (now - prev_time)

            # Block the (src, dst) pair if the rate exceeds the stated threshold
            if rate > THRESHOLD_PPS:
                self._block(dp, src, dst, rate)

    def _block(self, dp, src, dst, rate):
        """Blocks a (src, dst) pair."""
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src, ipv4_dst=dst)
        self._add_flow(dp, BLOCK_PRIORITY, match, [], hard_timeout=BLOCK_SECONDS)
        self.blocked.add((dp.id, src, dst))
        self.logger.warning(f"BLOCKED: {src} -> {dst} at {rate:.0f} pps")
