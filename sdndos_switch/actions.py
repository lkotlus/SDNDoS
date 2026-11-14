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

    def _rate_limit(self, dpid: int, src: str | None, dst: str, pps: int, seconds: int,
                    burst: int | None) -> bool: ...

    def _allow(self, dpid: int, src: str, dst: str, seconds: int) -> bool: ...

    def _limit_table_miss(self, dpid: int, pps: int, burst: int | None) -> bool: ...

    def _has_rule(self, kind: str, dpid: int, src: str | None, dst: str) -> bool: ...

    def _established_sources(self, dpid: int, dst: str, min_age: float) -> list[str]: ...

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
    
    def is_limited(self, dpid: int, src: str | None, dst: str) -> bool:
        """Whether src -> dst is rate limited."""
        return self._switch._has_rule("limit", dpid, src, dst)

    def rate_limit(self, dpid: int, src: str | None, dst: str, pps: int,
                   seconds: int = 0, burst: int | None = None) -> bool:
        """
        Drop (src -> dst) traffic above specified pps. Permanent if seconds is 0, and limit 
        covers all traffic to dst combined if src is None.
        """
        return self._switch._rate_limit(dpid, src, dst, pps, seconds, burst)

    def allow(self, dpid: int, src: str, dst: str, seconds: int = 0) -> bool:
        """
        Let (src -> dst) skip any lower priority mitigation rule, such as a rate
        limit on all traffic to dst. Blocks and per-source limits still apply.
        """
        return self._switch._allow(dpid, src, dst, seconds)

    def limit_table_miss(self, dpid: int, pps: int, burst: int | None = None) -> bool:
        """
        Cap how many unmatched packets per second the switch sends to the controller.
        Calling it again replaces the previous cap.
        """
        return self._switch._limit_table_miss(dpid, pps, burst)

    def established_sources(self, dpid: int, dst: str, min_age: float) -> list[str]:
        """
        Sources that first sent to dst at least min_age seconds ago and are still
        actively sending, not just holding an idle flow.
        """
        return self._switch._established_sources(dpid, dst, min_age)
