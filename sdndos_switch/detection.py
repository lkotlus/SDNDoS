"""
Detection strategy classes. Detection is not mitigation, so we
just observe traffic and create alerts based off of them.
"""

import ipaddress

from os_ken.lib.packet import packet

from sdndos_switch.models import Alert, PollWindow


class Detector:
    """Base detector class. Use as a parent, only override necessary hooks."""
    name = "none"

    def on_poll(self, window: PollWindow) -> list[Alert]:
        """Called once per completed round of flow stats polling."""
        return []

    def on_packet_in(self, dpid: int, pkt: packet.Packet, now: float) -> list[Alert]:
        """Called for every packet sent to the controller (table misses)."""
        return []


class ThresholdDetector(Detector):
    """
    Alerts when a single external host sends packets at a rate greater
    than a pre-determined threshold (measured in packets-per-second).
    """
    name = "threshold"

    def __init__(
        self, protected_net: str | ipaddress.IPv4Network | ipaddress.IPv6Network,
        threshold_pps: float
    ):
        self.protected_net = ipaddress.ip_network(protected_net)
        self.threshold_pps = threshold_pps

    def on_poll(self, window: PollWindow) -> list[Alert]:
        alerts = []
        for sample in window.samples:
            # Ignore server-to-external and server-to-server
            if (ipaddress.ip_address(sample.dst) not in self.protected_net
                    or ipaddress.ip_address(sample.src) in self.protected_net):
                continue

            # Make an alert for the (src, dst) pair if the rate exceeds the given threshold.
            if sample.pps > self.threshold_pps:
                alerts.append(Alert(
                    dpid=window.dpid,
                    time=window.time,
                    detector=self.name,
                    victim=sample.dst,
                    sources=(sample.src,),
                    detail=f"{sample.pps:.0f} pps",
                ))
        return alerts
