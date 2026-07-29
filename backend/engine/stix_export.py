"""STIX 2.1 export.

The counterpart to `sigma_import.py`: that module brings detection content
in from the outside world, this one sends incident content back out. An
incident here is a fact pattern that a threat-intel platform (or another
Sysmon Hunter, or a SOAR playbook) can consume without ever having to know
this engine's own schema -- STIX is the lingua franca IOC-correlation tools
already speak.

An incident becomes a small STIX bundle: one `identity` for this engine, one
`attack-pattern` per distinct ATT&CK technique the incident's detections
carry, one `indicator` per distinct pivotable value already surfaced by
`engine/indicators.py` (C2 destination IP/hostname, file hash, persistence
registry key), and one `report` tying all of it together with the incident's
own title and behavior-profile narrative as the description.

What this deliberately does NOT do: invent relationships the data does not
support. `build_indicators` is incident-level, not per-detection, so there is
no honest way to say "this specific IP indicates this specific technique" --
only "these were all observed as part of the same incident", which is
exactly what the report object's `object_refs` already expresses. A
`relationship` object claiming more precision than the source data has would
be STIX-shaped noise, not signal, so none are generated.

Object IDs are deterministic (UUIDv5, seeded on stable identifiers like a
technique ID or an indicator's own pattern string) rather than random, so
exporting the same incident twice -- or the same technique across two
different incidents -- produces the same STIX ID both times. That is what
lets a receiving platform de-duplicate objects across imports instead of
accumulating a new copy of "T1059.001" every time an analyst downloads a
bundle.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.engine.attack import attack_lookup
from backend.engine.indicators import build_indicators
from backend.engine.profile import build_profile

SPEC_VERSION = "2.1"

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _stix_id(sdo_type: str, seed: str) -> str:
    """A deterministic STIX identifier: `type--<uuidv5>`, seeded on content
    rather than randomly generated, so the same real-world object always maps
    to the same STIX object across exports (see module docstring)."""
    return f"{sdo_type}--{uuid.uuid5(uuid.NAMESPACE_URL, f'sysmon-hunter:{sdo_type}:{seed}')}"


IDENTITY_ID = _stix_id("identity", "sysmon-hunter")


def _stix_timestamp(value: Any) -> str:
    """Parse an ISO-8601 string (or accept a datetime) into the RFC 3339
    millisecond-precision, Z-suffixed form STIX 2.1 requires. Falls back to
    "now" for anything unparseable -- a malformed timestamp must not abort an
    export, the same policy the rest of this engine applies to bad input."""
    dt: datetime
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _escape_pattern_value(value: str) -> str:
    """Escape a value for use inside a single-quoted STIX pattern string.

    Per the STIX 2.1 patterning grammar, only backslash and single-quote are
    special inside a quoted string -- both are escaped with a backslash.
    Windows paths and registry keys are full of the former.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _basename(path: str | None) -> str:
    if not path:
        return "unknown"
    return path.replace("/", "\\").split("\\")[-1]


def _identity_object() -> dict[str, Any]:
    now = _stix_timestamp(None)
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": IDENTITY_ID,
        "created": now,
        "modified": now,
        "name": "Sysmon Hunter",
        "identity_class": "system",
        "description": "Sysmon detection and correlation engine.",
    }


def _attack_pattern_object(technique_id: str, timestamp: str) -> dict[str, Any]:
    """One `attack-pattern` SDO per ATT&CK technique ID, enriched from the
    local ATT&CK dataset (`engine/attack.py`) when available. A technique
    absent from that dataset still gets a valid, minimal object -- the
    technique ID itself is never lost, only the description."""
    data = attack_lookup.get(technique_id)
    name = data["name"] if data else technique_id
    description = (data or {}).get("description", "")
    url = (data or {}).get("url", f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}")
    tactics = (data or {}).get("tactics", [])

    obj: dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("attack-pattern", technique_id),
        "created": timestamp,
        "modified": timestamp,
        "created_by_ref": IDENTITY_ID,
        "name": name,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": technique_id, "url": url}
        ],
    }
    if description:
        # STIX descriptions are plain text; ATT&CK's own descriptions carry
        # markdown links and (Citation: ...) noise meant for a renderer, not
        # a machine consumer, so only the first paragraph is kept.
        obj["description"] = description.split("\n\n")[0]
    if tactics:
        obj["kill_chain_phases"] = [
            {"kill_chain_name": "mitre-attack", "phase_name": tactic} for tactic in tactics
        ]
    return obj


def _indicator(pattern: str, name: str, timestamp: str, indicator_types: list[str]) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("indicator", pattern),
        "created": timestamp,
        "modified": timestamp,
        "created_by_ref": IDENTITY_ID,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "indicator_types": indicator_types,
    }


def _indicator_objects(indicators: dict[str, Any], timestamp: str) -> list[dict[str, Any]]:
    """Turn `engine.indicators.build_indicators`'s output into `indicator`
    SDOs: one per distinct pivotable value, never one per detection -- two
    detections hitting the same C2 IP must not produce two indicators for it.
    """
    objects: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()

    def _add(pattern: str, name: str, types: list[str]) -> None:
        if pattern in seen_patterns:
            return
        seen_patterns.add(pattern)
        objects.append(_indicator(pattern, name, timestamp, types))

    for dest in indicators.get("destinations", []):
        ip = dest.get("ip")
        if ip:
            escaped = _escape_pattern_value(ip)
            kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
            _add(f"[{kind}:value = '{escaped}']", f"C2 destination {ip}", ["malicious-activity"])
        hostname = dest.get("hostname")
        if hostname:
            escaped = _escape_pattern_value(hostname)
            _add(f"[domain-name:value = '{escaped}']", f"C2 destination {hostname}", ["malicious-activity"])

    for entry in indicators.get("hashes", []):
        sha256 = entry.get("sha256")
        if sha256:
            escaped = _escape_pattern_value(sha256)
            image = entry.get("image", "unknown")
            _add(
                f"[file:hashes.SHA256 = '{escaped}']",
                f"{image} (SHA256 {sha256[:12]}...)",
                ["malicious-activity"],
            )

    for key in indicators.get("registry_persistence", []):
        escaped = _escape_pattern_value(key)
        _add(f"[windows-registry-key:key = '{escaped}']", f"Persistence key {key}", ["anomalous-activity"])

    return objects


def build_stix_bundle(incident: dict[str, Any], detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert one serialized incident (+ its detections) into a STIX 2.1
    Bundle dict, ready to `json.dumps`.

    `incident`/`detections` are the same serialized shapes
    `build_incident_report` takes (see `api/serializers.py`) -- this module
    reuses `engine/indicators.py` and `engine/profile.py` rather than
    re-deriving anything from raw events, so the STIX export and the PDF
    report can never disagree about what an incident's indicators are.
    """
    timestamp = _stix_timestamp(incident.get("first_seen"))
    modified = _stix_timestamp(incident.get("last_seen"))

    identity = _identity_object()
    attack_patterns = [
        _attack_pattern_object(t, timestamp) for t in incident.get("techniques", [])
    ]
    indicator_data = build_indicators(detections)
    indicator_objects = _indicator_objects(indicator_data, timestamp)

    profile = build_profile(incident, detections)
    description = profile.get("summary") or "No behavior profile available."

    labels = [incident.get("severity", "medium")]
    if incident.get("classification"):
        labels.append(incident["classification"])

    report_refs = [IDENTITY_ID] + [o["id"] for o in attack_patterns] + [o["id"] for o in indicator_objects]

    report = {
        "type": "report",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("report", incident.get("id", "")),
        "created": timestamp,
        "modified": modified,
        "created_by_ref": IDENTITY_ID,
        "name": incident.get("title") or "Suspicious activity",
        "description": description,
        "published": modified,
        "report_types": ["threat-report"],
        "labels": labels,
        "object_refs": report_refs,
        "external_references": [
            {"source_name": "sysmon-hunter", "external_id": incident.get("id", "")}
        ],
    }

    objects = [identity, *attack_patterns, *indicator_objects, report]

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
