"""Incident report endpoint.

Streams a PDF report for one incident. The report is generated on demand and
never written to disk -- it is built in memory and streamed straight to the
analyst, so there is no temporary file to clean up and nothing sensitive left
on the server.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from backend.api.serializers import serialize_detection_row, serialize_incident_row
from backend.engine.report import build_incident_report
from backend.models import db

router = APIRouter(tags=["report"])


@router.get("/incidents/{incident_id}/report")
async def incident_report(incident_id: str) -> Response:
    """Generate and stream a PDF report for one incident.

    404 if the incident is unknown. The filename is set from the incident id so
    a downloaded report is self-identifying in a folder of many.
    """
    incident = await db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No incident with id {incident_id}",
        )

    detection_rows = await db.get_incident_detections(incident_id)

    pdf_bytes = build_incident_report(
        incident=serialize_incident_row(incident),
        detections=[serialize_detection_row(d) for d in detection_rows],
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="incident-{incident_id}.pdf"',
        },
    )
