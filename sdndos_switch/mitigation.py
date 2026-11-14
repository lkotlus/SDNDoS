"""
Mitigation strategy classes. We react to alerts through 
network modifications here.
"""

from sdndos_switch.models import Alert

from sdndos_switch.actions import Actions


class Mitigator:
    """Base mitigator class. Use as a parent, only override necessary hooks."""
    name = "none"

    def on_alert(self, alert: Alert, actions: "Actions") -> None:
        """Called for every alert a detector raises."""

    def on_tick(self, now: float, actions: "Actions") -> None:
        """Called once per polling interval, for time-based decisions."""

    def on_block_removed(self, dpid: int, src: str, dst: str, actions: "Actions") -> None:
        """Called when the switch removes a block (such as an expired timeout)."""


class BlockSource(Mitigator):
    """
    Drops all traffic from each suspected source to the victim. Permanent
    block if block_seconds is 0.
    """
    name = "block_source"

    def __init__(self, block_seconds: int = 0):
        self.block_seconds = block_seconds

    def on_alert(self, alert: Alert, actions: "Actions") -> None:
        if alert.victim is None:
            return
        for src in alert.sources:
            if actions.block(alert.dpid, src, alert.victim, self.block_seconds):
                actions.logger.warning(f"BLOCKED: {src} -> {alert.victim} at {alert.detail}")
