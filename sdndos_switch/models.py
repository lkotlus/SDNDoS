"""
Dataclasses for what we pass between base switch, detectors, and mitigators.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowSample:
    """Traffic on one forwarding flow (src -> dst) since its previous sample."""
    src: str
    dst: str
    packets: int
    bytes: int
    elapsed: float  # In seconds (measured by the switch)

    @property
    def pps(self) -> float:
        return self.packets / self.elapsed


@dataclass(frozen=True)
class PollWindow:
    """Everything learned from one round of flow stats polling."""
    dpid: int
    time: float
    samples: list[FlowSample]
    blocked: frozenset[tuple[str, str]]  # (src, dst) pairs currently being dropped


@dataclass(frozen=True)
class Alert:
    """
    An alert raised by a detector. The victim and sources are optional (not all detectors
    can attribute an attack).
    """
    dpid: int
    time: float
    detector: str
    victim: str | None
    sources: tuple[str, ...]
    detail: str = ""
