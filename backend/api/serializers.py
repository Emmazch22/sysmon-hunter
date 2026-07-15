"""Wire formats.

Both the REST endpoints and the WebSocket feed emit detections and incidents. If
those two shapes ever drift apart, the console renders one way on page load and
a different way on live push -- a bug that is invisible in testing and obvious in
a demo. So there is exactly one function per object, used by both paths.

Both an in-memory domain object and a database row can be serialized, because
the console loads history from SQLite and receives live updates from the engine,
and must not be able to tell the difference.
"""

from __future__ import annotations

from typing import Any

from backend.models.db import DetectionRow, IncidentRow
from backend.models.schemas import Detection, Incident

_FORENSIC_FIELDS = {
    "User": "user",
    "IntegrityLevel": "integrity_level",
    "LogonId": "logon_id",
    "ProcessId": "process_id",
    "ParentProcessId": "parent_process_id",
    "ParentCommandLine": "parent_command_line",
    "CurrentDirectory": "current_directory",
    "Hashes": "hashes",
    "TerminalSessionId": "session_id",
    "OriginalFileName": "original_file_name",
    "Company": "company",
    "Product": "product",
    "DestinationIp": "destination_ip",
    "DestinationPort": "destination_port",
    "DestinationHostname": "destination_hostname",
    "TargetImage": "target_image",
    "TargetFilename": "target_filename",
    "TargetObject": "registry_key",
    "GrantedAccess": "granted_access",
    "PipeName": "pipe_name",
    "QueryName": "dns_query",
}


def _forensics(raw: dict[str, Any]) -> dict[str, Any]:
    """Pull investigation-relevant fields out of a raw Sysmon event. Only fields
    actually present are returned, so the block reflects what the event was."""
    return {
        label: raw[f]
        for f, label in _FORENSIC_FIELDS.items()
        if raw.get(f) not in (None, "")
    }


def serialize_detection(detection: Detection) -> dict[str, Any]:
    """A live detection, straight from the engine."""
    event = detection.event
    return {
        "rule_id": detection.rule_id,
        "title": detection.title,
        "severity": detection.severity.value,
        "attack": detection.attack,
        "host": event.host,
        "image": event.image,
        "parent_image": event.parent_image,
        "command_line": event.command_line,
        "process_guid": event.process_guid,
        "incident_id": detection.incident_id,
        "evidence": detection.evidence,
        "forensics": _forensics(event.raw),
        "matched_at": detection.matched_at.isoformat(),
    }


def serialize_detection_row(row: DetectionRow) -> dict[str, Any]:
    """A stored detection, replayed from the database on page load."""
    return {
        "rule_id": row.rule_id,
        "title": row.title,
        "severity": row.severity,
        "attack": row.attack or [],
        "host": row.host,
        "image": row.image,
        "parent_image": row.parent_image,
        "command_line": row.command_line,
        "process_guid": row.process_guid,
        "incident_id": row.incident_id,
        "evidence": row.evidence or {},
        "forensics": _forensics(row.raw_event or {}),
        "matched_at": row.matched_at.isoformat(),
    }


def serialize_incident(incident: Incident, actionable: bool) -> dict[str, Any]:
    """A live incident, straight from the correlator."""
    return {
        "id": incident.id,
        "title": incident.title,
        "host": incident.host,
        "severity": incident.severity.value,
        "score": incident.score,
        "detection_count": len(incident.detections),
        "chain": incident.chain,
        "process_tree": incident.process_tree,
        "techniques": incident.techniques,
        "actionable": actionable,
        "notes": "",
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
    }


def serialize_incident_row(row: IncidentRow) -> dict[str, Any]:
    """A stored incident, replayed from the database on page load."""
    return {
        "id": row.id,
        "title": row.title,
        "host": row.host,
        "severity": row.severity,
        "score": row.score,
        "detection_count": row.detection_count,
        "chain": row.chain or [],
        "process_tree": row.process_tree or [],
        "techniques": row.techniques or [],
        "actionable": bool(row.actionable),
        "notes": row.notes or "",
        "first_seen": row.first_seen.isoformat(),
        "last_seen": row.last_seen.isoformat(),
    }
