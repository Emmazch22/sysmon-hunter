"""Domain models.

These are the only shapes the rest of the codebase speaks. Winlogbeat JSON is
translated into an `Event` at the edge (see engine/normalizer.py) and never
leaks past it, so the detection engine stays independent of the transport.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    """Timezone-aware UTC now. Never use naive datetimes: correlation windows
    compare timestamps across events that may arrive from different hosts."""
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    """Severity of a rule or an incident."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Weights used to score incidents. The scale is deliberately non-linear: one
# critical detection should outweigh several medium ones, because a single
# LSASS access matters more than three suspicious-path executions.
SEVERITY_SCORE: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 5,
    Severity.HIGH: 8,
    Severity.CRITICAL: 14,
}

# Inverse mapping: a cumulative incident score is bucketed back into a severity
# so the UI can render incidents on the same scale as individual detections.
SCORE_BANDS: list[tuple[int, Severity]] = [
    # Calibrated against the severity weights above: a single critical (14) or
    # two highs (16) must land in the CRITICAL band, because an incident should
    # be able to outrank its worst individual rule -- that is the entire reason
    # to score incidents rather than just showing the max severity.
    (14, Severity.CRITICAL),
    (8, Severity.HIGH),
    (5, Severity.MEDIUM),
    (2, Severity.LOW),
    (0, Severity.INFO),
]


def score_to_severity(score: int) -> Severity:
    """Bucket a cumulative incident score into a severity level."""
    for floor, severity in SCORE_BANDS:
        if score >= floor:
            return severity
    return Severity.INFO


class Event(BaseModel):
    """A normalized Sysmon event, agnostic of how it reached us.

    Only the fields the engine reasons about are promoted to attributes. Every
    other Sysmon field stays in `raw`, which keeps the model stable while still
    letting rules reference exotic fields like `TargetObject` or `QueryName`.
    """

    event_id: int
    timestamp: datetime = Field(default_factory=utcnow)
    host: str = "unknown"
    user: Optional[str] = None

    # Process identity. These are what make the process tree possible: Sysmon
    # emits a GUID that is unique across reboots and PID reuse, unlike the PID.
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    process_id: Optional[int] = None

    image: Optional[str] = None
    parent_image: Optional[str] = None
    command_line: Optional[str] = None
    parent_command_line: Optional[str] = None

    # Anything Sysmon sent that we did not explicitly map.
    raw: dict[str, Any] = Field(default_factory=dict)

    def get(self, field: str) -> Any:
        """Resolve a field by name, checking normalized attributes first and
        falling back to the raw payload.

        This is what lets a rule say `image|endswith` (normalized) or
        `TargetObject|contains` (raw Sysmon) without the matcher needing to know
        the difference.
        """
        if field in type(self).model_fields:
            return getattr(self, field)
        return self.raw.get(field)


class Rule(BaseModel):
    """A detection rule, loaded from YAML.

    `detection` maps a field spec to the expected value(s). A field spec is
    `field` or `field|operator`, optionally suffixed with `|not` to negate.
    Supported operators: equals (default), contains, startswith, endswith, re.
    """

    id: str
    title: str
    event_id: int
    severity: Severity = Severity.MEDIUM
    attack: list[str] = Field(default_factory=list)
    description: str = ""
    detection: dict[str, Any]
    condition: str = "all"  # "all" -> AND across fields, "any" -> OR
    enabled: bool = True


class Detection(BaseModel):
    """A rule that fired against a specific event."""

    rule_id: str
    title: str
    severity: Severity
    attack: list[str] = Field(default_factory=list)
    event: Event
    matched_at: datetime = Field(default_factory=utcnow)

    # Set by the correlator once the detection is attached to an incident.
    incident_id: Optional[str] = None

    # Supporting numbers for detections that are not a simple field match.
    # A beacon detection puts its interval, jitter and regularity here, because
    # "beacon detected" on its own is an assertion, and an assertion is not
    # something an analyst can argue with when it turns out to be a false
    # positive. Rule-based detections leave this empty: the rule *is* the
    # evidence.
    evidence: dict[str, Any] = Field(default_factory=dict)

    @property
    def score(self) -> int:
        """Contribution of this detection to its incident's cumulative score."""
        return SEVERITY_SCORE[self.severity]


class ProcessNode(BaseModel):
    """A single process in the in-memory process tree.

    We keep the minimum needed to reconstruct an ancestry chain and render it.
    The full event is not retained: the tree may hold thousands of nodes and
    most of them will never appear in a detection.
    """

    guid: str
    parent_guid: Optional[str] = None
    host: str
    image: Optional[str] = None
    command_line: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)

    @property
    def name(self) -> str:
        """Bare executable name, e.g. `powershell.exe`."""
        if not self.image:
            return "unknown"
        return self.image.replace("/", "\\").split("\\")[-1]


class Incident(BaseModel):
    """A group of detections that share a process-tree root within a time window.

    This is the unit an analyst actually triages. A lone "PowerShell with an
    encoded command" is a lead; the same detection sitting under a WINWORD.EXE
    root alongside an outbound connection is an incident.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    host: str
    root_guid: str
    root_image: Optional[str] = None

    score: int = 0
    detections: list[Detection] = Field(default_factory=list)
    # Ancestry chain of the process that triggered the first detection, from
    # the root down to the process itself. Rendered directly by the console.
    chain: list[str] = Field(default_factory=list)

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)

    @property
    def severity(self) -> Severity:
        """Severity derived from the cumulative score, not from any one rule."""
        return score_to_severity(self.score)

    @property
    def techniques(self) -> list[str]:
        """Distinct ATT&CK techniques observed across all member detections."""
        seen: list[str] = []
        for detection in self.detections:
            for technique in detection.attack:
                if technique not in seen:
                    seen.append(technique)
        return sorted(seen)

    def add(self, detection: Detection) -> None:
        """Attach a detection and update the incident's running totals."""
        detection.incident_id = self.id
        self.detections.append(detection)
        self.score += detection.score
        self.last_seen = max(self.last_seen, detection.matched_at)
