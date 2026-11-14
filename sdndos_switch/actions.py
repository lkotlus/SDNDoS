"""
The interface mitigators use to modify the network.
"""

import logging
from typing import Protocol


class SwitchControl(Protocol):
    """Parts of the switch Actions needs (avoid circularity)."""
    blocked: set[tuple[int, str, str]]
    logger: logging.Logger

    def _block(self, dpid: int, src: str, dst: str, seconds: int) -> bool: ...


class Actions:
    """Interface mitigators use to modify the network."""

    def __init__(self, switch: SwitchControl):
        self._switch = switch
        self.logger = switch.logger

    def is_blocked(self, dpid: int, src: str, dst: str) -> bool:
        return (dpid, src, dst) in self._switch.blocked

    def block(self, dpid: int, src: str, dst: str, seconds: int = 0) -> bool:
        """
        Drop all traffic from src to dst, returns False if the pair is already
        blocked or the switch isn't connected.
        """
        return self._switch._block(dpid, src, dst, seconds)
