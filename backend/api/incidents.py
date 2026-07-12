"""Correlated incidents.

The endpoints an analyst actually works from. A detection is a lead; an incident
is the thing that gets triaged, and it carries the process chain and the ATT&CK
coverage that make triage possible.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from backend.api.serializers import serialize_detection_row, serialize_incident_row
from backend.models import db

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=500),
    actionable_only: bool = Query(
        default=False,
        description="Only incidents that crossed the score threshold, carry a "
        "critical detection, or hold three or more detections.",
    ),
) -> dict[str, Any]:
    """Most recent incidents, newest first.

    Newest-first here, unlike detections: an analyst opening the console wants
    the freshest incident at the top of the queue, not the bottom.
    """
    rows = await db.list_incidents(limit=limit, actionable_only=actionable_only)
    return {
        "returned": len(rows),
        "items": [serialize_incident_row(row) for row in rows],
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    """One incident with every detection that belongs to it, in the order they fired.

    This is the drill-down view: the incident summary answers "how bad", and the
    ordered detection list answers "what happened, in what sequence" -- which is
    the question that decides whether this is an intrusion or a false positive.
    """
    rows = await db.list_incidents(limit=500)
    incident = next((row for row in rows if row.id == incident_id), None)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No incident with id {incident_id}",
        )

    detections = await db.get_incident_detections(incident_id)
    return {
        **serialize_incident_row(incident),
        "detections": [serialize_detection_row(row) for row in detections],
    }