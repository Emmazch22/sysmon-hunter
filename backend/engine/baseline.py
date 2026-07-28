"""Behavioral baseline detection.

Every other detector in this engine looks for a known bad pattern: a rule
matches a specific field shape, beaconing matches a specific statistical
signature, discovery matches a specific set of recon commands. This detector
looks for the opposite thing -- not "is this bad" but "have we ever seen this
before on this host at all" -- which is what lets it catch what none of the
others can: a technique nobody has written a rule for yet.

The signal is deliberately narrow: one (host, image, parent image)
combination, never seen before. That is weak evidence on its own -- plenty of
first-time-seen processes are perfectly ordinary software update, a one-off
admin task -- which is why this always reports at low severity and never
alone justifies a verdict. Its job is to widen the net, not to replace the
rules that already catch the well-understood techniques.

Why this cannot be a YAML rule: a rule matches a field against a fixed
expected value known in advance. This is the mirror image -- flagging
whatever does *not* match a set of values nobody wrote down, because the set
itself is learned from the host's own history rather than authored by hand.

Off by default (see `Settings.behavior_baseline_enabled`), because a fresh
baseline has nothing learned yet, and enabling it against a host with no
history would flag its entire first stretch of ordinary activity. See the
learning-phase gate in `observe()` for how it avoids that even when enabled
against a host it has never watched before.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Optional

from backend.config import settings
from backend.models import db
from backend.models.schemas import Detection, Event, Severity

log = logging.getLogger(__name__)

# Sysmon EventID 1: a process was created.
PROCESS_CREATE = 1

BASELINE_RULE_ID = "BSL-001"


def _short(image: Optional[str]) -> str:
    """Bare executable name for a readable title, e.g. `powershell.exe`."""
    if not image:
        return "unknown"
    return image.replace("/", "\\").split("\\")[-1]


class BaselineDetector:
    """Flags a (host, image, parent image) combination a host has never shown
    before.

    Long-term memory, not a session cache: what a host has "seen before"
    spans its whole history, not just the current process's uptime, so the
    known set is loaded from `baseline_observations` once at startup via
    `load()` and kept in memory from then on -- a database round trip per
    process-creation event would not scale, and is not needed, since a write
    only happens the first time a combination is ever seen.

    The learning-phase gate is per host and based on how many distinct
    combinations that host has *already* contributed, not on events processed
    this session. That distinction matters: it means a host with a mature,
    already-learned baseline starts alerting again immediately after a
    restart, while a host this detector has genuinely never watched gets the
    same quiet learning period a first run would.
    """

    def __init__(self, learning_events: int = 50) -> None:
        self._learning_events = learning_events
        self._known: set[tuple[str, str, str]] = set()
        self._host_combo_counts: dict[str, int] = defaultdict(int)

    async def load(self) -> None:
        """Populate the in-memory known set from the database. Called once at
        startup, alongside the rule store and the ATT&CK lookup."""
        rows = await db.list_baseline_observations()
        for row in rows:
            self._known.add((row.host, row.image, row.parent_image))
            self._host_combo_counts[row.host] += 1
        if rows:
            log.info(
                "Baseline detector loaded %d known combination(s) across %d host(s)",
                len(rows),
                len(self._host_combo_counts),
            )

    async def observe(self, event: Event) -> Optional[Detection]:
        """Feed one process-creation event in. Returns a Detection the first
        time a host shows a genuinely new (image, parent image) pair, once
        that host is past its learning phase."""
        if event.event_id != PROCESS_CREATE:
            return None

        image = event.image or "unknown"
        parent = event.parent_image or "unknown"
        host = event.host
        key = (host, image, parent)

        if key in self._known:
            return None

        # Genuinely new. Learn it before deciding whether to report it -- a
        # crash between learning and reporting should never re-teach the same
        # combination twice.
        self._known.add(key)
        still_learning = self._host_combo_counts[host] < self._learning_events
        self._host_combo_counts[host] += 1
        await db.record_baseline_observation(host, image, parent, event.timestamp)

        if still_learning:
            return None

        return self._build_detection(event, host, image, parent)

    def _build_detection(
        self, event: Event, host: str, image: str, parent: str
    ) -> Detection:
        log.info("Baseline: new combination on %s: %s <- %s", host, image, parent)
        return Detection(
            rule_id=BASELINE_RULE_ID,
            title=f"First-seen process on {host}: {_short(image)} (parent: {_short(parent)})",
            severity=Severity.LOW,
            attack=[],
            event=event,
            matched_at=event.timestamp,
            evidence={
                "host": host,
                "image": image,
                "parent_image": parent,
                "host_known_combinations": self._host_combo_counts[host],
            },
        )

    @property
    def hosts_tracked(self) -> int:
        """Number of hosts with at least one learned combination."""
        return len(self._host_combo_counts)


# Module-level singleton, loaded once at startup (see main.py's lifespan).
# Not owned or recreated by Pipeline.reset(): its memory is long-term and
# database-backed, unlike the beacon/discovery detectors' short, in-memory
# windows, and a database reset (detections/incidents) is a different action
# from forgetting a host's learned behavior.
baseline_detector = BaselineDetector(learning_events=settings.baseline_learning_events)
