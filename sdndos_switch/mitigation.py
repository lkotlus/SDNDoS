"""
Mitigation strategy classes. We react to alerts through 
network modifications here.
"""

from sdndos_switch.models import Alert, MitigationRule
from sdndos_switch.actions import Actions

# AGENTMSG: OpenFlow timeouts are 16 bit, so no rule can last longer than this
MAX_RULE_SECONDS = 65535


class Mitigator:
    """Base mitigator class. Use as a parent, only override necessary hooks."""
    name = "none"

    def on_alert(self, alert: Alert, actions: Actions) -> None:
        """Called for every alert a detector raises."""

    def on_tick(self, now: float, actions: Actions) -> None:
        """Called once per polling interval, for time-based decisions."""

    def on_switch_connected(self, dpid: int, actions: Actions) -> None:
        """Called when the switch removes a block (such as an expired timeout)."""

    def on_rule_removed(self, rule: MitigationRule, actions: Actions) -> None:
        """Called when the switch removes a block (such as an expired timeout)."""


class CombinedMitigator(Mitigator):
    """
    Runs several mitigators side-by-side, each getting every hook in order.
    """

    def __init__(self, *mitigators: Mitigator):
        self.mitigators = mitigators
        self.name = "+".join(m.name for m in mitigators)

    def on_alert(self, alert: Alert, actions: Actions) -> None:
        for m in self.mitigators:
            m.on_alert(alert, actions)

    def on_tick(self, now: float, actions: Actions) -> None:
        for m in self.mitigators:
            m.on_tick(now, actions)

    def on_switch_connected(self, dpid: int, actions: Actions) -> None:
        for m in self.mitigators:
            m.on_switch_connected(dpid, actions)

    def on_rule_removed(self, rule: MitigationRule, actions: Actions) -> None:
        for m in self.mitigators:
            m.on_rule_removed(rule, actions)


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


class EscalatingBlock(Mitigator):
    """
    Temporarily blocks each suspected source to the victim. Multiplicative exponential
    increase for repeated offenses. A record is wiped clean after forgive_seconds without
    an incident.
    """
    name = "escalating_block"

    def __init__(self, base_seconds: int = 10, factor: float = 3, max_seconds: int = 3600,
                 forgive_seconds: float = 600):
        if not 1 <= base_seconds <= max_seconds <= MAX_RULE_SECONDS:
            raise ValueError(f"Need 1 <= base_seconds <= max_seconds <= {MAX_RULE_SECONDS}")
        self.base_seconds = base_seconds
        self.factor = factor
        self.max_seconds = max_seconds
        self.forgive_seconds = forgive_seconds
        self.offenses: dict[tuple[int, str, str], tuple[int, float]] = {}  # key: (count, block end)

    def on_alert(self, alert: Alert, actions: Actions) -> None:
        if alert.victim is None:
            return
        for src in alert.sources:
            key = (alert.dpid, src, alert.victim)
            if actions.is_blocked(*key):
                continue

            offenses, last_end = self.offenses.get(key, (0, None))
            if last_end is not None and alert.time - last_end > self.forgive_seconds:
                offenses = 0
            offenses += 1
            seconds = int(min(self.base_seconds * self.factor ** (offenses - 1), self.max_seconds))

            if actions.block(alert.dpid, src, alert.victim, seconds):
                self.offenses[key] = (offenses, alert.time + seconds)
                actions.logger.warning(
                    f"BLOCKED: {src} -> {alert.victim} at {alert.detail} "
                    f"for {seconds}s (offense {offenses})"
                )


class RateLimitSource(Mitigator):
    """
    Cap traffic to a pps limit rather than a full ban. Rate limits are permanent if seconds
    is 0. The detection pps should be greater than the rate limit pps.
    """
    name = "rate_limit_source"

    def __init__(self, pps: int = 50, seconds: int = 0, burst: int | None = None):
        self.pps = pps
        self.seconds = seconds
        self.burst = burst

    def on_alert(self, alert: Alert, actions: Actions) -> None:
        if alert.victim is None:
            return
        for src in alert.sources:
            if actions.rate_limit(alert.dpid, src, alert.victim, self.pps, self.seconds, self.burst):
                actions.logger.warning(
                    f"LIMITED: {src} -> {alert.victim} at {alert.detail}, capped to {self.pps} pps"
                )


class ProtectVictim(Mitigator):
    """
    Caps ALL traffic to the victim at pps, trusts sources not in the alert after 
    trust_after seconds. Sources in the alert are never trusted.
    """
    name = "protect_victim"

    def __init__(self, pps: int = 100, seconds: int = 30, trust_after: float = 30.0,
                 burst: int | None = None):
        if seconds < 1:
            raise ValueError("ProtectVictim needs a timeout, a permanent victim-wide limit never lifts")
        self.pps = pps
        self.seconds = seconds
        self.trust_after = trust_after
        self.burst = burst

    def on_alert(self, alert: Alert, actions: Actions) -> None:
        if alert.victim is None:
            return
        if not actions.rate_limit(alert.dpid, None, alert.victim, self.pps, self.seconds, self.burst):
            return

        trusted = [
            src for src in actions.established_sources(alert.dpid, alert.victim, self.trust_after)
            if src not in alert.sources
        ]
        for src in trusted:
            actions.allow(alert.dpid, src, alert.victim, self.seconds)
        actions.logger.warning(
            f"PROTECTING: {alert.victim} at {alert.detail}, capped to {self.pps} pps "
            f"for {self.seconds}s, trusting {len(trusted)} source(s): {', '.join(trusted) or 'none'}"
        )


class ProtectController(Mitigator):
    """
    Puts a permanent cap on the pps of all sources combined to any given destination. This
    means spoofed sources or distributed attacks will not work, but it does bottleneck the 
    network.
    """
    name = "protect_controller"

    def __init__(self, pps: int = 500, burst: int | None = None):
        self.pps = pps
        self.burst = burst

    def on_switch_connected(self, dpid: int, actions: Actions) -> None:
        if actions.limit_table_miss(dpid, self.pps, self.burst):
            actions.logger.info(f"CONTROLLER LIMIT: switch {dpid} capped to {self.pps} pps")
