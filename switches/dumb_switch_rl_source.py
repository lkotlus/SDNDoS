"""
Creates a learning switch that implements the most basic possible DoS
rule. If an external host sends packets to a server faster than a given
threshold, it rate limits the (src, dst) pair.
"""

import ipaddress

from sdndos_switch.base import BaseSwitch
from sdndos_switch.detection import ThresholdDetector
from sdndos_switch.mitigation import RateLimitSource

# Currently hardcoded network range for servers
SERVER_NET = ipaddress.ip_network("10.0.0.0/24")
# Also hardcoded packet per second threshold
THRESHOLD_PPS = 200
# Capped pps after rate limit
CAP_PPS = 100


class DumbSwitch(BaseSwitch):
    def make_detector(self):
        return ThresholdDetector(SERVER_NET, THRESHOLD_PPS)

    def make_mitigator(self):
        return RateLimitSource(CAP_PPS)
