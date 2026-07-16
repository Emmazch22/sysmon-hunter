"""Incident triage status.

Whether an incident is still open, closed as handled, or dismissed as a false
positive. Set only from here -- the engine's correlator upsert never touches
this field, the same separation notes.py keeps for the analyst's free-text note.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi import status as http_status
from pydantic import BaseModel, field_validator

from backend.api.serializers import serialize_incident_row
from backend.models import db
from backend.models.schemas import IncidentStatus

router = APIRouter(tags=["status"])


class StatusUpdate(BaseModel):
    status: IncidentStatus

    @field_validator("status", mode="before")
    @classmethod
    def _normalize(cls, value: Any) -> Any:
        # Accept "Closed", "CLOSED", etc. -- an analyst's client should not have
        # to match the wire value's exact case to close an incident.
        return value.lower() if isinstance(value, str) else value


@router.put("/incidents/{incident_id}/status")
async def set_status(incident_id: str, update: StatusUpdate) -> dict[str, Any]:
    """Close an incident, mark it a false positive, or reopen it.

    Any of the three states can transition to any other -- a closed incident
    can be reopened if new evidence surfaces, and a false positive can be
    reopened the same way. There is no workflow to enforce here, only a value
    to record; the analyst is the one doing the triage, not this endpoint.
    """
    row = await db.update_incident_status(incident_id, update.status.value)
    if row is None:
        raise HTTPException(
            http_status.HTTP_404_NOT_FOUND, f"No incident {incident_id}"
        )
    return serialize_incident_row(row)
