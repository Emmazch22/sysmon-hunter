"""Incident behavior-profile endpoint.

Returns the narrative account of what an incident's malware did, for the console
and the PDF report. Read-only; derived on demand from the incident's detections.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from backend.api.serializers import serialize_detection_row, serialize_incident_row
from backend.engine.profile import build_profile
from backend.models import db

router = APIRouter(tags=["profile"])


@router.get("/incidents/{incident_id}/profile")
async def incident_profile(incident_id: str) -> dict[str, Any]:
    """Return the behavior profile: a summary sentence and ordered kill-chain phases."""
    rows = await db.list_incidents(limit=500)
    incident = next((r for r in rows if r.id == incident_id), None)
    if incident is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"No incident with id {incident_id}"
        )

    detections = await db.get_incident_detections(incident_id)
    return build_profile(
        serialize_incident_row(incident),
        [serialize_detection_row(d) for d in detections],
    )
