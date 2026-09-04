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


class IncidentStatus(str, Enum):
    """An incident's triage state.

    Set by the analyst, never by the engine: the correlator's upsert only
    ever inserts a new row as OPEN and must never overwrite this field on an
    existing one, the same way it never touches notes. CLOSED means "handled,
    nothing more to do"; FALSE_POSITIVE means "handled, and it wasn't real" --
    kept distinct from CLOSED so the console (and eventually a metric) can
    tell "resolved" from "resolved, the rule was wrong."
    """

    OPEN = "open"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


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


# ---------------------------------------------------------------------------
# Incident titling.
#
# An incident identified only by a hex id forces the analyst to expand it to
# learn what it is. A derived title fixes that: it names the *story* the
# incident tells -- "Phishing to reconnaissance", "Credential theft" -- from the
# tactics and signature rules present, so the queue is readable at a glance.
# ---------------------------------------------------------------------------

# Each technique maps to the tactic it serves. A title built from tactics reads
# as a narrative an analyst recognises, not a list of rule IDs.
#
# This is a deliberately different, finer-grained breakdown than
# `engine/profile.py`'s TECHNIQUE_TACTIC, not a copy of it that has drifted.
# Profile.py groups by MITRE's actual kill-chain phase because it needs one
# clean phrase per phase ("evaded defenses", "accessed credential material");
# this one splits a few of those phases further (`download`, `masquerading`,
# `injection` are all real MITRE *techniques*, elevated to their own tag here)
# because a one-line title reads better as "Process masquerading on HOST"
# than the generic "Defense evasion on HOST" both of those cases would
# otherwise collapse into. The two are allowed to disagree on which single
# tactic best describes a technique; what they must not do is silently drop
# a technique the rule corpus actually ships, which is what `_tactic_for()`
# below and the parent-fallback in `profile.py` both guard against.
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1566": "delivery",
    "T1566.001": "delivery",
    "T1204": "execution",
    "T1204.001": "execution",
    "T1204.002": "execution",
    "T1204.004": "execution",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1027": "execution",
    "T1105": "download",
    "T1218": "download",
    "T1218.011": "download",
    "T1547.001": "persistence",
    "T1546.012": "persistence",
    "T1685": "defense-evasion",
    "T1562.001": "defense-evasion",
    "T1036.005": "masquerading",
    "T1003.001": "credential-access",
    "T1552.001": "credential-access",
    "T1003": "credential-access",
    "T1087": "discovery",
    "T1082": "discovery",
    "T1016": "discovery",
    "T1033": "discovery",
    "T1069": "discovery",
    "T1018": "discovery",
    "T1057": "discovery",
    "T1049": "discovery",
    "T1046": "discovery",  # SCN-001 network scan detector
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1573": "command-and-control",
    "T1055": "injection",
    "T1490": "impact",
    # Added when the SYS-093..123 rule batches turned out to have shipped with
    # no entry here at all -- see TestRuleCorpusTechniquesResolve in
    # tests/test_titles.py, which now fails the build if this happens again.
    "T1190": "initial-access",
    "T1047": "execution",
    "T1569.002": "execution",
    "T1070.001": "defense-evasion",
    "T1070.004": "defense-evasion",
    "T1127.001": "defense-evasion",
    "T1134": "defense-evasion",
    "T1134.001": "defense-evasion",  # SYS-204
    "T1140": "defense-evasion",
    "T1197": "defense-evasion",
    "T1202": "defense-evasion",
    "T1211": "defense-evasion",
    "T1216": "defense-evasion",
    "T1548.002": "defense-evasion",
    "T1562.004": "defense-evasion",
    "T1558.003": "credential-access",
    "T1482": "discovery",
    "T1021.001": "lateral-movement",
    "T1021.002": "lateral-movement",
    "T1021.006": "lateral-movement",
    "T1563.002": "lateral-movement",
    "T1550.002": "lateral-movement",
    "T1550.003": "lateral-movement",
    "T1053.005": "persistence",
    "T1098": "persistence",
    "T1136.001": "persistence",
    "T1505.003": "persistence",
    "T1543.003": "persistence",
    "T1546.003": "persistence",
    "T1546.015": "persistence",
    "T1560.001": "collection",
    "T1113": "collection",
    "T1115": "collection",
    "T1074": "collection",
    "T1119": "collection",
    "T1090.001": "command-and-control",
    "T1571": "command-and-control",
    "T1219": "command-and-control",
    "T1102": "command-and-control",
    "T1567.002": "exfiltration",
    "T1486": "impact",
    "T1489": "impact",
    "T1491.001": "impact",
    "T1485": "impact",
    "T1531": "impact",
    "T1484.001": "privilege-escalation",
    "T1484.002": "privilege-escalation",
    # SYS-169..174. (T1047 already mapped above, for SYS-078.)
    "T1552.004": "credential-access",
    "T1552.005": "credential-access",
    "T1021.003": "lateral-movement",
    "T1611": "privilege-escalation",
    # SYS-124..131.
    "T1568": "command-and-control",
    "T1070.006": "defense-evasion",
    "T1564.004": "defense-evasion",
    "T1006": "defense-evasion",
    # SYS-132..150. T1218.008/T1218.014 grouped with their parent T1218 as
    # "download" for consistency with T1218.011 above, even though these two
    # are proxy-execution rather than download techniques strictly speaking --
    # the parent-fallback in _tactic_for() would resolve them the same way
    # anyway, this just makes the mapping explicit rather than implicit.
    "T1218.008": "download",
    "T1218.014": "download",
    "T1555.003": "credential-access",
    "T1555": "credential-access",
    "T1083": "discovery",
    "T1518.001": "discovery",
    "T1048": "exfiltration",
    "T1558.004": "credential-access",
    # SYS-175..190.
    "T1546.008": "persistence",
    "T1547.004": "persistence",
    "T1547.005": "persistence",
    "T1547.014": "persistence",
    "T1136.002": "persistence",
    "T1562.002": "defense-evasion",
    "T1562.009": "defense-evasion",
    "T1036.007": "masquerading",
    "T1204.003": "execution",
    "T1003.004": "credential-access",
    "T1003.005": "credential-access",
    "T1558.001": "credential-access",
    "T1552.002": "credential-access",
    "T1552.006": "credential-access",
    "T1021.004": "lateral-movement",
    "T1090.003": "command-and-control",
    "T1560.002": "collection",
    # SYS-191..196.
    "T1562.006": "defense-evasion",
    "T1112": "defense-evasion",
    "T1564.001": "defense-evasion",
    # SYS-197..199.
    "T1574.001": "defense-evasion",
    "T1574.002": "defense-evasion",
    "T1553.004": "defense-evasion",
    # SYS-205..220.
    "T1055.012": "injection",
    "T1059.005": "execution",
    "T1003.003": "credential-access",
    # SYS-221..239.
    "T1218.007": "execution",
    "T1220": "execution",
    "T1556.002": "credential-access",
    "T1056.001": "credential-access",
    "T1558": "credential-access",
    # SYS-240..246.
    "T1546.001": "persistence",
    "T1546.002": "persistence",
    "T1546.007": "persistence",
    "T1546.009": "persistence",
    "T1546.010": "persistence",
    "T1546.011": "persistence",
    "T1546.013": "persistence",
}


def _tactic_for(technique: str) -> Optional[str]:
    """Look up a technique's narrative tag, falling back to its parent
    technique when the exact sub-technique is not listed above.

    Without this, a rule that declares only a sub-technique ID not spelled
    out in `_TECHNIQUE_TACTIC` (e.g. a new rule shipped with `T1055.001` but
    the table only has `T1055`) silently contributes nothing to the title --
    not the parent's tactic, nothing -- and an incident whose only technique
    is that sub-technique falls all the way through to the generic
    "Suspicious activity" title. `AttackLookup.get()` (engine/attack.py)
    already does the same parent fallback for the technique-description
    modal; this mirrors it here for the same reason.
    """
    tactic = _TECHNIQUE_TACTIC.get(technique)
    if tactic is not None:
        return tactic
    if "." in technique:
        return _TECHNIQUE_TACTIC.get(technique.split(".")[0])
    return None


# Rules whose presence alone names the incident -- unambiguous, high-signal
# findings that outrank any narrative built from tactics.
_SIGNATURE_RULES: dict[str, str] = {
    "SYS-004": "Ransomware preparation",  # shadow copy deletion
    "SYS-041": "Credential theft",  # LSASS access
    "SYS-038": "IIS credential theft",  # appcmd password dump
    "SYS-010": "Credential theft",
    "SYS-060": "Named-pipe C2",  # Cobalt Strike / Meterpreter pipe
    "SYS-031": "Defender tampering",
    "SYS-151": "ClickFix social engineering",  # decoy-lure paste from Explorer
    "BCN-001": "C2 beacon",
    "DSC-001": "Host reconnaissance",
    "SCN-001": "Network scan",
}

# Tactic combinations that tell a familiar multi-stage story. Ordered most
# specific first; the first whose tactics are all present wins.
_NARRATIVES: list[tuple[set[str], str]] = [
    ({"delivery", "execution", "discovery"}, "Phishing to reconnaissance"),
    ({"delivery", "execution", "command-and-control"}, "Phishing to C2"),
    ({"credential-access", "command-and-control"}, "Credential access with C2"),
    ({"delivery", "execution"}, "Phishing execution chain"),
    ({"execution", "command-and-control"}, "Execution with C2"),
    ({"discovery", "command-and-control"}, "Reconnaissance with C2"),
    ({"credential-access", "discovery"}, "Credential access after recon"),
]

# Correlation chains: named, high-confidence multi-stage patterns expressed as
# rule-ID co-occurrence, richer than the generic tactic-only _NARRATIVES above
# because they name a specific attack story ("ransomware", not just "impact
# after credential access"). Checked before _NARRATIVES, so a matching chain
# always wins over the more generic tactic-based title.
#
# Each entry is (classification slug, title, [requirement, ...]), where a
# requirement is (minimum_count, {candidate rule IDs}) -- the incident's
# detections must include at least `minimum_count` distinct rule IDs from that
# set. All requirements in the list must be satisfied (AND across
# requirements); within one requirement, any `minimum_count` of its rule IDs
# satisfy it (OR, with a floor).
#
# This is deliberately a rule-ID pattern match producing a title and
# classification label, not a score bonus. The spec that requested these
# three chains asked for flat point bonuses added on top of SEVERITY_SCORE
# (+150/+300/+500) -- incompatible with this engine's existing, carefully
# calibrated weights, where a single CRITICAL detection already scores 14 and
# two HIGHs (16) already clear the CRITICAL band through pure stacking (see
# SCORE_BANDS above). Adding arbitrary bonus points on top would make the
# score stop meaning "how bad are the individual findings" and break that
# calibration for every incident, not just these three patterns. What a chain
# buys instead is identity: a specific, named classification and title an
# analyst recognises instantly -- the actionability a bonus was meant to
# guarantee is already there, because every rule referenced below is itself
# HIGH or CRITICAL, so any chain that matches already scores well past the
# actionable threshold on the existing scale.
_CORRELATION_CHAINS: list[tuple[str, str, list[tuple[int, set[str]]]]] = [
    (
        "ransomware",
        "Ransomware activity chain",
        [
            (1, {"SYS-004"}),  # shadow copy / backup destruction
            (1, {"SYS-080", "SYS-081"}),  # ransom note or encrypted-extension write
        ],
    ),
    (
        "credential-theft-campaign",
        "Credential theft campaign",
        [
            (
                2,
                {
                    "SYS-010",  # LSASS access
                    "SYS-041",  # LSASS access (credential-dumping access rights)
                    "SYS-130",  # DCSync-style directory replication request
                    "SYS-131",  # Mimikatz module referenced on the command line
                    "SYS-135",  # non-browser process touched a browser credential DB
                    "SYS-136",  # script interpreter touched a KeePass database
                    "SYS-137",  # browser credential DB written into a staging dir
                    "SYS-118",  # Kerberoasting
                    "SYS-150",  # AS-REP roasting
                },
            ),
        ],
    ),
    (
        "office-to-powershell",
        "Office to PowerShell infection chain",
        [
            (1, {"SYS-001"}),  # Office application spawned a command interpreter
            # Deliberately SYS-009 (download cradle) only, not SYS-002 (encoded
            # command): SYS-001+SYS-002 is the exact combination the existing
            # "Phishing execution chain" narrative test already covers, and
            # this chain is meant to be a *more* specific story layered on
            # top of that one, not a silent retitling of it. A download
            # cradle fetching a second stage is the sharper, unambiguous
            # signal that this is specifically an infection chain rather
            # than any encoded-command execution following an Office spawn.
            (1, {"SYS-009"}),
        ],
    ),
]


# A lone tactic, made readable for the fallback title.
_TACTIC_LABEL: dict[str, str] = {
    "delivery": "Phishing delivery",
    "initial-access": "Initial access",
    "execution": "Suspicious execution",
    "download": "Payload download",
    "persistence": "Persistence",
    "defense-evasion": "Defense evasion",
    "masquerading": "Process masquerading",
    "credential-access": "Credential access",
    "discovery": "Host reconnaissance",
    "lateral-movement": "Lateral movement",
    "privilege-escalation": "Privilege escalation",
    "collection": "Data collection",
    "command-and-control": "C2 communication",
    "exfiltration": "Data exfiltration",
    "injection": "Process injection",
    "impact": "Destructive activity",
}


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
    # Full branching process tree the incident spans (flat node records).
    process_tree: list[dict] = Field(default_factory=list)

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

    @property
    def correlation_chain(self) -> Optional[tuple[str, str]]:
        """The first `_CORRELATION_CHAINS` pattern this incident's rule IDs
        satisfy, as `(classification slug, title)`, or None.

        Derived, like `title`, from the incident's current detections every
        time it is read -- so a chain that becomes complete as more
        detections land is picked up immediately, with no re-scoring step.
        """
        rule_ids = {d.rule_id for d in self.detections}
        for classification, name, requirements in _CORRELATION_CHAINS:
            if all(len(rule_ids & candidates) >= minimum for minimum, candidates in requirements):
                return classification, name
        return None

    @property
    def classification(self) -> Optional[str]:
        """Machine-readable slug for the matched correlation chain, if any
        (e.g. "ransomware"), for UI badges and filtering. None when no chain
        matches -- most incidents will not classify this specifically."""
        chain = self.correlation_chain
        return chain[0] if chain is not None else None

    @property
    def title(self) -> str:
        """A human-readable summary of what this incident is.

        Derived, never stored: it always reflects the incident's current
        contents, so a title generated when the incident held one detection
        updates itself as more land. Priority is a named correlation chain
        first (the most specific possible story), then a tactic-based
        narrative (a multi-stage story with no chain of its own), then a
        signature rule, then the dominant single tactic.
        """
        chain = self.correlation_chain
        if chain is not None:
            return f"{chain[1]} on {self.host}"

        tactics = {_tactic_for(t) for t in self.techniques}
        tactics.discard(None)

        # 1. A multi-stage narrative whose tactics are all present.
        for needed, name in _NARRATIVES:
            if needed <= tactics:
                return f"{name} on {self.host}"

        # 2. A signature rule that names the incident on its own.
        rule_ids = {d.rule_id for d in self.detections}
        for rule_id, name in _SIGNATURE_RULES.items():
            if rule_id in rule_ids:
                return f"{name} on {self.host}"

        # 3. The single dominant tactic, made readable.
        if tactics:
            label = _TACTIC_LABEL.get(sorted(tactics)[0], "Suspicious activity")
            return f"{label} on {self.host}"

        return f"Suspicious activity on {self.host}"

    def add(self, detection: Detection) -> None:
        """Attach a detection and update the incident's running totals."""
        detection.incident_id = self.id
        self.detections.append(detection)
        self.score += detection.score
        self.last_seen = max(self.last_seen, detection.matched_at)
