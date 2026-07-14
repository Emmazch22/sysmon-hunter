"""Discovery-burst detection.

An attacker who has just landed on a host orients themselves: who am I, what
privileges do I have, what domain is this, who else is on the network. Each
command in that sequence is legitimate on its own — an administrator runs
`whoami` and `systeminfo` every day — so no single-event rule can flag them
without burying the console in noise.

The signal is the *burst*: several **distinct** reconnaissance commands, in the
same process tree, in a short window. Distinctness is the whole design. A
monitoring script that runs `systeminfo` every five minutes produces volume but
no variety; an attived attacker fingerprinting a host produces variety fast. So
this counts unique techniques, not raw executions — running `whoami` fifty times
is one data point, running whoami + net + nltest + systeminfo is four and looks
like an intrusion.

Why this cannot be a YAML rule: the same reason as beaconing. A rule matches one
event; a burst only exists across several, and the thing being measured is how
many *different kinds* of recon share a process-tree root within a window.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from backend.engine.correlator import ProcessTree
from backend.models.schemas import Detection, Event, Severity, utcnow

log = logging.getLogger(__name__)

# Sysmon EventID 1: a process was created.
PROCESS_CREATE = 1

DISCOVERY_RULE_ID = "DSC-001"
DISCOVERY_TECHNIQUES = ["T1087", "T1082", "T1016", "T1033", "T1069", "T1018"]


# Each entry maps a recognizable recon action to the ATT&CK technique it serves.
# Grouping matters: `net user` and `net group` are both account discovery
# (T1087), so hitting both should count as *one* kind of recon, not two. The
# detector counts distinct techniques, and this table is what defines "distinct".
#
# Patterns are matched against the full, lowercased command line, because the
# same technique wears many faces: `whoami`, `whoami /all`, and
# `whoami /groups` are one action, and native tools have LOLBin equivalents
# (`wmic`, PowerShell cmdlets) an attacker reaches for precisely to look benign.
DISCOVERY_SIGNATURES: list[tuple[str, str, str]] = [
    # (technique, label, regex against the lowercased command line)
    #
    # Order matters where patterns overlap: the more specific signature must come
    # first. `net group "domain admins"` is privileged-group enumeration (T1069),
    # a sharper signal than plain account discovery (T1087) -- so it is listed
    # ahead of the generic `net group`, which would otherwise claim it.
    ("T1069", "permission groups", r'\bnet\d?\s+group\s+"?domain admins'),
    ("T1069", "permission groups", r"\bnltest\b|\bget-adgroupmember\b"),
    ("T1033", "current user", r"\bwhoami\b"),
    ("T1087", "account discovery", r"\bnet\d?\s+(user|group|localgroup|accounts)\b"),
    ("T1087", "account discovery", r"\bget-aduser\b|\bget-adgroup\b|\bdsquery\b"),
    ("T1016", "network config", r"\bipconfig\b|\bnetsh\b|\bget-netipconfiguration\b"),
    ("T1016", "network config", r"\bnbtstat\b|\barp\s+-a\b|\broute\s+print\b"),
    ("T1082", "system info", r"\bsysteminfo\b|\bwmic\s+(os|computersystem|bios)\b"),
    ("T1082", "system info", r"\bget-wmiobject\b|\bget-ciminstance\b"),
    ("T1018", "remote systems", r"\bnet\d?\s+view\b|\bdsquery\s+computer\b"),
    ("T1057", "process discovery", r"\btasklist\b|\bget-process\b|\bqprocess\b"),
    ("T1049", "network connections", r"\bnetstat\b\s+-[a-z]*n"),
]

# Precompiled once. The detector runs this against every process-creation
# command line on a busy host, so compiling per event would be pure waste.
_COMPILED: list[tuple[str, str, re.Pattern[str]]] = [
    (technique, label, re.compile(pattern, re.IGNORECASE))
    for technique, label, pattern in DISCOVERY_SIGNATURES
]


def classify(command_line: Optional[str]) -> Optional[tuple[str, str]]:
    """Return (technique, label) if a command line is reconnaissance, else None.

    The first signature to match wins. Order in the table is therefore
    significant only where patterns could overlap; in practice they are
    disjoint enough that order does not change the verdict, only which label is
    reported when two describe the same command.
    """
    if not command_line:
        return None
    for technique, label, pattern in _COMPILED:
        if pattern.search(command_line):
            return technique, label
    return None


class _Burst:
    """The recon activity seen under one process-tree root."""

    def __init__(self) -> None:
        # technique -> (earliest seen, latest seen, example command line).
        # Keyed by technique so repeats of the same kind collapse to one entry —
        # that collapse is the point of the whole detector.
        self.techniques: dict[str, tuple[datetime, datetime, str]] = {}
        self.host: str = "unknown"
        self.root_image: Optional[str] = None
        self.last_alert: Optional[datetime] = None

    def record(self, technique: str, when: datetime, command_line: str) -> None:
        existing = self.techniques.get(technique)
        if existing is None:
            self.techniques[technique] = (when, when, command_line)
        else:
            first, _, example = existing
            self.techniques[technique] = (first, when, example)

    def distinct_count(self) -> int:
        return len(self.techniques)

    def span(self) -> float:
        """Seconds between the first and last recon command in the burst."""
        if not self.techniques:
            return 0.0
        firsts = [first for first, _, _ in self.techniques.values()]
        lasts = [last for _, last, _ in self.techniques.values()]
        return (max(lasts) - min(firsts)).total_seconds()


class DiscoveryDetector:
    """Flags clusters of distinct reconnaissance commands in one process tree.

    Bursts are grouped by the tree root, not by the process that ran each
    command, because a real recon sequence is spread across children: the
    attacker's foothold spawns `cmd`, which runs `whoami`, then `net`, then
    `nltest`. Grouping by the individual process would see three unrelated
    single commands; grouping by the root sees one burst.
    """

    def __init__(
        self,
        tree: ProcessTree,
        min_distinct: int = 4,
        window: timedelta = timedelta(minutes=5),
        cooldown: timedelta = timedelta(minutes=15),
    ) -> None:
        self._tree = tree
        # How many *distinct* recon techniques constitute a burst. Four is the
        # point where "an admin checking something" becomes "someone mapping the
        # host": a legitimate task rarely needs whoami and net and nltest and
        # systeminfo within minutes of each other.
        self._min_distinct = min_distinct
        self._window = window
        self._cooldown = cooldown

        # root_guid (per host) -> burst
        self._bursts: dict[tuple[str, str], _Burst] = defaultdict(_Burst)

    def observe(self, event: Event) -> Optional[Detection]:
        """Feed one process-creation event in. Returns a Detection on a burst."""
        if event.event_id != PROCESS_CREATE:
            return None

        hit = classify(event.command_line)
        if hit is None:
            return None

        technique, _label = hit

        # Group under the tree root. The recon command usually runs deep in the
        # tree, but the burst belongs to the whole intrusion, whose identity is
        # the root.
        guid = event.process_guid or f"orphan:{event.host}"
        root = self._tree.root(event.host, guid)
        key = (event.host, root)

        burst = self._bursts[key]
        burst.host = event.host
        if burst.root_image is None:
            chain = self._tree.ancestry(event.host, guid)
            burst.root_image = chain[0].image if chain else event.image

        # Drop recon that has aged out of the window before counting, so a slow
        # trickle of one command every ten minutes never accumulates into a
        # phantom burst.
        self._expire(burst, now=event.timestamp)
        burst.record(technique, event.timestamp, event.command_line or "")

        return self._assess(key, burst, event)

    def _expire(self, burst: _Burst, now: datetime) -> None:
        """Forget recon last seen before the window opened."""
        cutoff = now - self._window
        burst.techniques = {
            technique: (first, last, example)
            for technique, (first, last, example) in burst.techniques.items()
            if last >= cutoff
        }

    def _assess(
        self, key: tuple[str, str], burst: _Burst, event: Event
    ) -> Optional[Detection]:
        """Decide whether the accumulated recon is a burst worth reporting."""
        if burst.distinct_count() < self._min_distinct:
            return None

        if burst.last_alert and event.timestamp - burst.last_alert < self._cooldown:
            return None

        burst.last_alert = event.timestamp
        return self._build_detection(burst, event)

    def _build_detection(self, burst: _Burst, event: Event) -> Detection:
        """Package a confirmed burst as a Detection.

        Severity scales with breadth: the more different kinds of recon in the
        window, the more this looks like methodical enumeration rather than an
        administrator who happened to run a couple of diagnostic commands.
        """
        count = burst.distinct_count()
        severity = Severity.HIGH if count >= 5 else Severity.MEDIUM

        techniques = sorted(burst.techniques.keys())
        examples = [example for _, _, example in burst.techniques.values()]

        # The burst is a *set* of recon commands, not one. Attaching the single
        # command line of whichever event happened to confirm the burst is
        # misleading -- it makes the detection look like it fired on that one
        # command. The full list lives in the evidence panel, so the detection's
        # own command_line is cleared to avoid showing an arbitrary (and possibly
        # unrelated) command in the row.
        burst_event = event.model_copy(update={"command_line": None})

        log.info(
            "Discovery burst on %s: %d distinct recon techniques in %.0fs",
            burst.host,
            count,
            burst.span(),
        )

        return Detection(
            rule_id=DISCOVERY_RULE_ID,
            title=(
                f"Reconnaissance burst: {count} distinct discovery techniques "
                f"in {burst.span():.0f}s"
            ),
            severity=severity,
            attack=techniques,
            event=burst_event,
            matched_at=event.timestamp,
            evidence={
                "distinct_techniques": count,
                "techniques": techniques,
                "span_seconds": round(burst.span()),
                "commands": examples[:8],  # a sample, not the full history
            },
        )

    def prune(self, now: Optional[datetime] = None) -> int:
        """Drop bursts whose recon has entirely aged out. Returns count removed."""
        now = now or utcnow()
        cutoff = now - self._window

        stale = []
        for key, burst in self._bursts.items():
            latest = max(
                (last for _, last, _ in burst.techniques.values()), default=None
            )
            if latest is None or latest < cutoff:
                stale.append(key)

        for key in stale:
            del self._bursts[key]
        return len(stale)

    @property
    def tracked_bursts(self) -> int:
        """Number of process trees with recon activity under observation."""
        return len(self._bursts)
