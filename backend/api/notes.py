"""Incident notes.

A free-text analyst note attached to an incident, editable only from the
incident's full-page view. The note belongs to the analyst and persists until
they change or delete it; the engine's upsert never touches it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi import status as http_status
from pydantic import BaseModel

from backend.api.serializers import serialize_incident_row
from backend.models import db

router = APIRouter(tags=["notes"])

# A note is a summary, not a report. 500 words keeps it bounded.
MAX_NOTES_WORDS = 500


class NoteUpdate(BaseModel):
    notes: str


@router.put("/incidents/{incident_id}/notes")
async def set_notes(incident_id: str, update: NoteUpdate) -> dict[str, Any]:
    """Set the incident's note (plain text, 500-word limit)."""
    word_count = len(update.notes.split())
    if word_count > MAX_NOTES_WORDS:
        raise HTTPException(
            http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Notes are {word_count} words; the limit is {MAX_NOTES_WORDS}.",
        )
    row = await db.update_incident_notes(incident_id, update.notes)
    if row is None:
        raise HTTPException(
            http_status.HTTP_404_NOT_FOUND, f"No incident {incident_id}"
        )
    return serialize_incident_row(row)


@router.delete("/incidents/{incident_id}/notes")
async def delete_notes(incident_id: str) -> dict[str, Any]:
    """Clear the incident's note."""
    row = await db.update_incident_notes(incident_id, "")
    if row is None:
        raise HTTPException(
            http_status.HTTP_404_NOT_FOUND, f"No incident {incident_id}"
        )
    return serialize_incident_row(row)
