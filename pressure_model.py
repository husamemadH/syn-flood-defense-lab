"""Fixed, in-memory comparison fixtures. This module has no networking code."""
from collections import deque
from dataclasses import dataclass

CAPACITY = 32
PROBES_PER_TICK = 4
TICKS = 6
DEFAULT_REQUESTS = PROBES_PER_TICK * TICKS
REQUEST_PROFILES = (DEFAULT_REQUESTS, 100, 250, 500)
RETENTION_TICKS = 3
PER_SOURCE_CAP = 2


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    source_pattern: str
    per_source: bool = False
    automated: bool = False
    upstream_limited: bool = False


SCENARIOS = (
    Scenario("baseline", "Baseline", "none"),
    Scenario("open-single", "No defense / single source", "single"),
    Scenario("open-distributed", "No defense / changing sources", "changing"),
    Scenario("filter-single", "Per-source firewall / single source", "single", per_source=True),
    Scenario("filter-distributed", "Per-source firewall / changing sources", "changing", per_source=True),
    Scenario("auto-success", "Automated defense / recovery", "changing", per_source=True, automated=True),
    Scenario("auto-failure", "Automated defense / upstream bottleneck", "changing",
             per_source=True, automated=True, upstream_limited=True),
)


@dataclass(frozen=True)
class Window:
    tick: int
    syn_recv_count: int
    syn_ack_ratio: float | None
    pressure_arrivals: int
    per_source_drops: int
    cookie_bypasses: int
    queue_drops: int
    upstream_drops: int
    decisions: tuple[str, ...]


class QueueModel:
    def __init__(self, scenario):
        self.scenario = scenario
        self.cookies = False
        self.expirations = deque()
        self.upstream_remainder = 0

    def enable_cookies(self):
        self.cookies = True

    def step(self, tick, probe_count=PROBES_PER_TICK):
        while self.expirations and self.expirations[0] <= tick:
            self.expirations.popleft()
        pressure = tick >= 2 and self.scenario.source_pattern != "none"
        groups = ()
        if pressure:
            groups = (38,) if self.scenario.source_pattern == "single" else (2,) * 19

        arrivals = sum(groups)
        admitted = (sum(min(count, PER_SOURCE_CAP) for count in groups)
                    if self.scenario.per_source else arrivals)
        tracked = min(admitted, CAPACITY - len(self.expirations))
        self.expirations.extend([tick + RETENTION_TICKS] * tracked)

        upstream = probe_count
        if pressure and self.scenario.upstream_limited:
            upstream, self.upstream_remainder = divmod(probe_count + self.upstream_remainder, 4)
        backlog_full = len(self.expirations) == CAPACITY
        # Sequential legitimate probes can reuse an available slot after each handshake.
        completed = upstream if self.cookies or not backlog_full else 0
        decisions = (("served",) * completed
                     + ("backlog",) * (upstream - completed)
                     + ("upstream",) * (probe_count - upstream))
        pressure_overflow = admitted - tracked
        return Window(
            tick=tick, syn_recv_count=len(self.expirations),
            syn_ack_ratio=round((admitted + upstream) / completed, 2) if completed else None,
            pressure_arrivals=arrivals, per_source_drops=arrivals - admitted,
            cookie_bypasses=(pressure_overflow + (completed if backlog_full else 0)) if self.cookies else 0,
            queue_drops=0 if self.cookies else pressure_overflow + upstream - completed,
            upstream_drops=probe_count - upstream, decisions=decisions,
        )
