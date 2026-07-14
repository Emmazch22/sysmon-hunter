"""Incident triage: status, classification, and analyst notes.

The SOC workflow the engine cannot do on its own. Detection and correlation are
automatic; deciding whether an incident is a true positive, working it, and
closing it is the analyst's job. This endpoint is the only writer of those
fields -- the engine's upsert never touches them.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi import status as http_status
from pydantic import BaseModel

from backend.api.serializers import serialize_incident_row
from backend.models import db

router = APIRouter(tags=["triage"])

# The lifecycle states and analyst verdicts the UI offers. Validated server-side
# so a malformed request cannot put an incident into an unknown state.
VALID_STATUS = {"new", "in_progress", "closed"}
VALID_CLASSIFICATION = {"", "tp", "fp", "tp_benign", "inconclusive"}

# Analyst notes are free text but bounded: a triage note is a summary, not a
# report. 500 words is generous for that and keeps the field from becoming a
# dumping ground that bloats the row and the incident list payload.
MAX_NOTES_WORDS = 500


class TriageUpdate(BaseModel):
    """A partial update: any field left None is unchanged."""

    status: Optional[str] = None
    classification: Optional[str] = None
    notes: Optional[str] = None


@router.patch("/incidents/{incident_id}/triage")
async def update_triage(incident_id: str, update: TriageUpdate) -> dict[str, Any]:
    """Update an incident's status, classification and/or notes.

    A PATCH, not a PUT: the analyst changes one thing at a time (adds a note,
    then later closes), and each change must not clobber the others.
    """
    if update.status is not None and update.status not in VALID_STATUS:
        raise HTTPException(
            http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Invalid status {update.status!r}. Expected one of {sorted(VALID_STATUS)}.",
        )
    if (
        update.classification is not None
        and update.classification not in VALID_CLASSIFICATION
    ):
        raise HTTPException(
            http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Invalid classification {update.classification!r}.",
        )
    if update.notes is not None:
        word_count = len(update.notes.split())
        if word_count > MAX_NOTES_WORDS:
            raise HTTPException(
                http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"Notes are {word_count} words; the limit is {MAX_NOTES_WORDS}.",
            )

    row = await db.update_incident_triage(
        incident_id,
        status=update.status,
        classification=update.classification,
        notes=update.notes,
    )
    if row is None:
        raise HTTPException(
            http_status.HTTP_404_NOT_FOUND, f"No incident {incident_id}"
        )

    return serialize_incident_row(row)
