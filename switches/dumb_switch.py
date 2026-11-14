"""
Creates a learning switch that implements the most basic possible DoS
rule. If an external host sends packets to a server faster than a given
threshold, it blocks the (src, dst) pair, permanently or for BLOCK_SECONDS.
"""

import ipaddress

from sdndos_switch.base import BaseSwitch
from sdndos_switch.detection import ThresholdDetector
from sdndos_switch.mitigation import BlockSource

# Currently hardcoded network range for servers
SERVER_NET = ipaddress.IPv4Network(ipaddress.ip_network("10.0.0.0/24"))
# Also hardcoded packet per second threshold
THRESHOLD_PPS = 200
# If BLOCK_SECONDS is 0, the block is permanent
BLOCK_SECONDS = 0


class DumbSwitch(BaseSwitch):
    def make_detector(self):
        return ThresholdDetector(SERVER_NET, THRESHOLD_PPS)

    def make_mitigator(self):
        return BlockSource(BLOCK_SECONDS)
