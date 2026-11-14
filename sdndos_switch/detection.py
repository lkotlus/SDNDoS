"""
Detection strategy classes. Detection is not mitigation, so we
just observe traffic and create alerts based off of them.
"""

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from os_ken.lib.packet import ipv4, packet

from sdndos_switch.models import Alert, FlowSample, PollWindow

Network = str | ipaddress.IPv4Network | ipaddress.IPv6Network


class Detector:
    """Base detector class. Use as a parent, only override necessary hooks."""
    name = "none"

    def on_poll(self, window: PollWindow) -> list[Alert]:
        """Called once per completed round of flow stats polling."""
        return []

    def on_packet_in(self, dpid: int, in_port: int, pkt: packet.Packet, now: float) -> list[Alert]:
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


def _inbound_rates(samples: list[FlowSample], protected_net) -> dict[str, dict[str, float]]:
    """Rates of external -> protected traffic in one window, as {victim: {source: pps}}."""
    rates: dict[str, dict[str, float]] = defaultdict(dict)
    for sample in samples:
        if (ipaddress.ip_address(sample.dst) in protected_net
                and ipaddress.ip_address(sample.src) not in protected_net):
            rates[sample.dst][sample.src] = sample.pps
    return rates


def _suspects(per_source: dict[str, float], min_share: float) -> tuple[str, ...]:
    """
    Sources sending at least min_share of the victim's total, heaviest first. Used
    by detectors that work on totals but can still point at likely attackers.
    """
    total = sum(per_source.values())
    if total <= 0:
        return ()
    heavy = [src for src, pps in per_source.items() if pps >= min_share * total]
    return tuple(sorted(heavy, key=lambda src: -per_source[src]))


class CombinedDetector(Detector):
    """
    Runs several detectors side by side and passes on every alert any of them raises.
    E.g. CombinedDetector(ThresholdDetector(...), PacketInRateDetector(...)).
    """

    def __init__(self, *detectors: Detector):
        self.detectors = detectors
        self.name = "+".join(d.name for d in detectors)

    def on_poll(self, window: PollWindow) -> list[Alert]:
        return [alert for d in self.detectors for alert in d.on_poll(window)]

    def on_packet_in(self, dpid: int, in_port: int, pkt: packet.Packet, now: float) -> list[Alert]:
        return [alert for d in self.detectors for alert in d.on_packet_in(dpid, in_port, pkt, now)]


class AggregateDetector(Detector):
    """
    Alerts when total rate of external traffic to one server goes over the threshold no matter
    how many sources that number is spread across. This catches distributed attacks, but is still
    a naive threshold approach. Sources sending at least min_share of the total pps are suspects,
    and you can just set min_share to None if you don't want suspects named.
    """
    name = "aggregate"

    def __init__(self, protected_net: Network, threshold_pps: float, min_share: float | None = 0.05):
        self.protected_net = ipaddress.ip_network(protected_net)
        self.threshold_pps = threshold_pps
        self.min_share = min_share

    def on_poll(self, window: PollWindow) -> list[Alert]:
        alerts = []
        for victim, per_source in _inbound_rates(window.samples, self.protected_net).items():
            total = sum(per_source.values())
            if total > self.threshold_pps:
                sources = _suspects(per_source, self.min_share) if self.min_share is not None else ()
                alerts.append(Alert(
                    dpid=window.dpid,
                    time=window.time,
                    detector=self.name,
                    victim=victim,
                    sources=sources,
                    detail=f"{total:.0f} pps total from {sum(1 for pps in per_source.values() if pps > 0)} source(s)",
                ))
        return alerts


@dataclass
class _Baseline:
    """Exponentially weighted mean and variance of one server's inbound rate."""
    mean: float = 0.0
    var: float = 0.0
    samples: int = 0
    over: int = 0  # consecutive windows above the limit

    def update(self, x: float, alpha: float):
        if self.samples == 0:
            self.mean = x
        else:
            diff = x - self.mean
            incr = alpha * diff
            self.mean += incr
            self.var = (1 - alpha) * (self.var + diff * incr)
        self.samples += 1


class AdaptiveDetector(Detector):
    """
    Learns normal inbound traffic paterns for each server (moving average and deviation of total
    rate) and alerts when the rate stays above $mean + k * derivation$ for a set number of windows
    (sustain) in a row. No alerts are triggered during the warmup window, and min_pps is used as a 
    floor for relatively inactive servers. Attack windows aren't used in the baseline calculation,
    so attack-level traffic is never marked as normal.
    """
    name = "adaptive"

    def __init__(self, protected_net: Network, k: float = 4.0, alpha: float = 0.1,
                 min_pps: float = 50, warmup: int = 10, sustain: int = 2,
                 min_share: float | None = 0.05):
        self.protected_net = ipaddress.ip_network(protected_net)
        self.k = k
        self.alpha = alpha
        self.min_pps = min_pps
        self.warmup = warmup
        self.sustain = sustain
        self.min_share = min_share
        self.baselines: dict[tuple[int, str], _Baseline] = {}  # (dpid, server): baseline

    def on_poll(self, window: PollWindow) -> list[Alert]:
        rates = _inbound_rates(window.samples, self.protected_net)
        # Known servers with no inbound samples this window had a rate of 0
        victims = set(rates) | {v for (d, v) in self.baselines if d == window.dpid}

        alerts = []
        for victim in sorted(victims):
            per_source = rates.get(victim, {})
            total = sum(per_source.values())
            base = self.baselines.setdefault((window.dpid, victim), _Baseline())

            if base.samples < self.warmup:
                base.update(total, self.alpha)
                continue

            std = math.sqrt(base.var)
            limit = max(base.mean + self.k * std, self.min_pps)
            if total <= limit:
                base.over = 0
                base.update(total, self.alpha)
                continue

            base.over += 1
            if base.over >= self.sustain:
                sources = _suspects(per_source, self.min_share) if self.min_share is not None else ()
                alerts.append(Alert(
                    dpid=window.dpid,
                    time=window.time,
                    detector=self.name,
                    victim=victim,
                    sources=sources,
                    detail=f"{total:.0f} pps vs baseline {base.mean:.0f} +/- {std:.0f} pps",
                ))
        return alerts


class EntropyDetector(Detector):
    """
    Measures how inbound traffic is spread over the servers as normalized Shannon entropy. Alerts
    whenever it stays at or below a set max_entropy for a set number of windows (sustain) while the
    total inbound rate is at least min_pps. Normalization uses all servers seen so far, so at least
    two are required. This counts both forwarded traffic (flow stats) and packets sent to the controller.
    This means that floods with spoofed sources don't fly under the radar.
    """
    name = "entropy"

    def __init__(self, protected_net: Network, max_entropy: float = 0.5, min_pps: float = 100,
                 sustain: int = 2, min_share: float | None = 0.05):
        self.protected_net = ipaddress.ip_network(protected_net)
        self.max_entropy = max_entropy
        self.min_pps = min_pps
        self.sustain = sustain
        self.min_share = min_share
        self.known: dict[int, set[str]] = defaultdict(set)  # dpid: protected servers seen
        self.over: dict[int, int] = defaultdict(int)  # dpid: consecutive low-entropy windows
        self._packet_ins: dict[int, Counter[str]] = defaultdict(Counter)  # dpid: {dst: count}
        self._last_poll: dict[int, float] = {}

    def on_packet_in(self, dpid: int, in_port: int, pkt: packet.Packet, now: float) -> list[Alert]:
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None:
            dst, src = ipaddress.ip_address(ip.dst), ipaddress.ip_address(ip.src)  # type: ignore
            if dst in self.protected_net and src not in self.protected_net:
                self._packet_ins[dpid][str(dst)] += 1
        return []

    def on_poll(self, window: PollWindow) -> list[Alert]:
        dpid = window.dpid
        rates = _inbound_rates(window.samples, self.protected_net)
        packet_ins = self._packet_ins.pop(dpid, Counter())
        last = self._last_poll.get(dpid)
        self._last_poll[dpid] = window.time
        if last is None or window.time <= last:
            return []
        interval = window.time - last

        # Per-server rate: forwarded traffic plus traffic that went to the controller
        load: dict[str, float] = defaultdict(float)
        for victim, per_source in rates.items():
            load[victim] += sum(per_source.values())
        for dst, n in packet_ins.items():
            load[dst] += n / interval

        self.known[dpid].update(load)
        total = sum(load.values())
        servers = len(self.known[dpid])
        if servers < 2 or total <= 0:
            self.over[dpid] = 0
            return []

        entropy = -sum((x / total) * math.log2(x / total) for x in load.values() if x > 0)
        normalized = abs(entropy) / math.log2(servers)
        if total < self.min_pps or normalized > self.max_entropy:
            self.over[dpid] = 0
            return []

        self.over[dpid] += 1
        if self.over[dpid] < self.sustain:
            return []
        victim = max(load, key=lambda dst: load[dst])
        sources = _suspects(rates.get(victim, {}), self.min_share) if self.min_share is not None else ()
        return [Alert(
            dpid=dpid,
            time=window.time,
            detector=self.name,
            victim=victim,
            sources=sources,
            detail=f"entropy {normalized:.2f} over {servers} servers at {total:.0f} pps",
        )]


class PacketInRateDetector(Detector):
    """
    Alerts in the event of a switch port sending unmatched packets to the controller faster 
    than a given threshold for a set number of windows (sustain) in a row. Normal traffic 
    only reaches the controller for the first packets of a new flood, so a high sustained
    rate indicates a flood of new flows (typically spoofed sources). Reports the port due to
    spoofed source addresses being useless.
    """
    name = "packet_in_rate"

    def __init__(self, threshold_pps: float = 100, sustain: int = 2,
                 protected_net: Network | None = None):
        self.threshold_pps = threshold_pps
        self.sustain = sustain
        self.protected_net = ipaddress.ip_network(protected_net) if protected_net is not None else None
        self._counts: dict[int, Counter[int]] = defaultdict(Counter)  # dpid: {port: count}
        self._dsts: dict[tuple[int, int], Counter[str]] = defaultdict(Counter)  # (dpid, port): {dst: n}
        self._over: dict[tuple[int, int], int] = defaultdict(int)  # (dpid, port): windows over
        self._last_poll: dict[int, float] = {}

    def on_packet_in(self, dpid: int, in_port: int, pkt: packet.Packet, now: float) -> list[Alert]:
        self._counts[dpid][in_port] += 1
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None:
            self._dsts[(dpid, in_port)][ip.dst] += 1  # type: ignore
        return []

    def on_poll(self, window: PollWindow) -> list[Alert]:
        dpid = window.dpid
        counts = self._counts.pop(dpid, Counter())
        dsts = {port: self._dsts.pop((dpid, port), Counter()) for port in counts}
        last = self._last_poll.get(dpid)
        self._last_poll[dpid] = window.time
        if last is None or window.time <= last:
            return []
        interval = window.time - last

        alerts = []
        for port in {p for (d, p) in self._over if d == dpid} | set(counts):
            rate = counts.get(port, 0) / interval
            if rate <= self.threshold_pps:
                self._over.pop((dpid, port), None)
                continue
            self._over[(dpid, port)] += 1
            if self._over[(dpid, port)] < self.sustain:
                continue

            victim = None
            if dsts.get(port):
                top = dsts[port].most_common(1)[0][0]
                if self.protected_net is None or ipaddress.ip_address(top) in self.protected_net:
                    victim = top
            alerts.append(Alert(
                dpid=dpid,
                time=window.time,
                detector=self.name,
                victim=victim,
                sources=(),
                detail=f"{rate:.0f} packet-ins/s on port {port}",
                ports=(port,),
            ))
        return alerts
