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
        "incident_id": detection.incident_id,
        "evidence": detection.evidence,
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
        "incident_id": row.incident_id,
        "evidence": row.evidence or {},
        "matched_at": row.matched_at.isoformat(),
    }


def serialize_incident(incident: Incident, actionable: bool) -> dict[str, Any]:
    """A live incident, straight from the correlator."""
    return {
        "id": incident.id,
        "host": incident.host,
        "severity": incident.severity.value,
        "score": incident.score,
        "detection_count": len(incident.detections),
        "chain": incident.chain,
        "techniques": incident.techniques,
        "actionable": actionable,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
    }


def serialize_incident_row(row: IncidentRow) -> dict[str, Any]:
    """A stored incident, replayed from the database on page load."""
    return {
        "id": row.id,
        "host": row.host,
        "severity": row.severity,
        "score": row.score,
        "detection_count": row.detection_count,
        "chain": row.chain or [],
        "techniques": row.techniques or [],
        "actionable": bool(row.actionable),
        "first_seen": row.first_seen.isoformat(),
        "last_seen": row.last_seen.isoformat(),
    }
