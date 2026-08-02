"""In-process Prometheus-style metrics.

No `prometheus_client` dependency -- this project runs as a single process
with no multi-worker, multi-instance scrape-aggregation problem to solve, so
a couple of hand-rolled counter/histogram classes rendering the exposition
format directly are enough. Same "content not code" bias this project
already applies elsewhere (STIX export and the PDF manual are both
hand-built rather than reaching for a heavier library to save a few dozen
lines).

Exposition format: https://prometheus.io/docs/instrumenting/exposition_formats/
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Sequence

_LabelKey = tuple[tuple[str, str], ...]


def _label_key(labels: dict[str, str]) -> _LabelKey:
    return tuple(sorted(labels.items()))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(pairs: Sequence[tuple[str, str]]) -> str:
    if not pairs:
        return ""
    body = ",".join(f'{k}="{_escape(v)}"' for k, v in pairs)
    return "{" + body + "}"


class Counter:
    """A monotonically increasing count, optionally split by label.

    Never decreases and never resets except on process restart -- the one
    Prometheus invariant that lets a scraper compute a rate from two
    samples without the server having to track deltas itself.
    """

    def __init__(self, name: str, help_text: str) -> None:
        self.name = name
        self.help_text = help_text
        self._values: dict[_LabelKey, int] = defaultdict(int)

    def inc(self, amount: int = 1, **labels: str) -> None:
        self._values[_label_key(labels)] += amount

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        for key in sorted(self._values):
            lines.append(f"{self.name}{_format_labels(key)} {self._values[key]}")
        return lines


# Sub-second buckets: this is a local single-collector app answering
# requests in milliseconds under normal operation, not a distributed
# service where multi-second tail latency is the interesting case.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
)


class Histogram:
    """A cumulative-bucket histogram, Prometheus's native latency shape.

    `observe()` increments every bucket whose boundary is at or above the
    observed value, which is already the cumulative count a Prometheus
    histogram's `_bucket{le=...}` series requires -- no separate
    running-total pass needed at render time.
    """

    def __init__(
        self, name: str, help_text: str, buckets: Sequence[float] = DEFAULT_BUCKETS
    ) -> None:
        self.name = name
        self.help_text = help_text
        self.buckets = tuple(buckets)
        self._bucket_counts: dict[_LabelKey, list[int]] = defaultdict(
            lambda: [0] * len(self.buckets)
        )
        self._sum: dict[_LabelKey, float] = defaultdict(float)
        self._count: dict[_LabelKey, int] = defaultdict(int)

    def observe(self, value: float, **labels: str) -> None:
        key = _label_key(labels)
        counts = self._bucket_counts[key]
        for i, boundary in enumerate(self.buckets):
            if value <= boundary:
                counts[i] += 1
        self._sum[key] += value
        self._count[key] += 1

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]
        for key in sorted(self._count):
            counts = self._bucket_counts[key]
            for i, boundary in enumerate(self.buckets):
                le_key = key + (("le", str(boundary)),)
                lines.append(f"{self.name}_bucket{_format_labels(le_key)} {counts[i]}")
            inf_key = key + (("le", "+Inf"),)
            lines.append(f"{self.name}_bucket{_format_labels(inf_key)} {self._count[key]}")
            lines.append(f"{self.name}_sum{_format_labels(key)} {self._sum[key]}")
            lines.append(f"{self.name}_count{_format_labels(key)} {self._count[key]}")
        return lines


# --- Module-level instruments the rest of the app increments. ---
# A single shared registry, the same reasoning as rule_store and pipeline
# being module-level singletons: one process, one set of counters.

ingest_requests_total = Counter(
    "hunter_ingest_requests_total",
    "Events posted to /ingest, by outcome (accepted, malformed, rate_limited).",
)

detections_total = Counter(
    "hunter_detections_total",
    "Detections raised, by rule ID.",
)

http_requests_total = Counter(
    "hunter_http_requests_total",
    "HTTP requests handled, by method, route, and status code.",
)

http_request_duration_seconds = Histogram(
    "hunter_http_request_duration_seconds",
    "HTTP request handling time in seconds, by method and route.",
)

_START_TIME = time.monotonic()


def uptime_seconds() -> float:
    """How long this process has been running. Resets to zero on restart,
    which is itself useful signal -- a scraper watching this gauge dip to
    zero learns the collector restarted without needing a separate event."""
    return time.monotonic() - _START_TIME


def render_prometheus_text(extra_gauges: dict[str, float] | None = None) -> str:
    """Render every registered instrument plus a caller-supplied set of
    point-in-time gauges (pipeline stats, connection counts) as one
    Prometheus text-exposition payload.

    Gauges are passed in rather than tracked as module state here, because
    they already live somewhere else with a clearer reason to own them
    (Pipeline.stats, the WebSocket manager's connection count) -- this
    function's job is only to format them, not to duplicate their source of
    truth.
    """
    lines: list[str] = []
    lines.append("# HELP hunter_uptime_seconds Seconds since this process started.")
    lines.append("# TYPE hunter_uptime_seconds gauge")
    lines.append(f"hunter_uptime_seconds {uptime_seconds():.3f}")

    for name, value in (extra_gauges or {}).items():
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")

    lines.extend(ingest_requests_total.render())
    lines.extend(detections_total.render())
    lines.extend(http_requests_total.render())
    lines.extend(http_request_duration_seconds.render())

    return "\n".join(lines) + "\n"
