"""Incident report endpoints.

Two export formats for the same incident, both generated on demand and never
written to disk: a PDF for a human to read, and a STIX 2.1 bundle for another
tool to ingest. Both are built in memory and streamed straight out, so there
is no temporary file to clean up and nothing sensitive left on the server.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from backend.api.serializers import serialize_detection_row, serialize_incident_row
from backend.engine.report import build_incident_report
from backend.engine.stix_export import build_stix_bundle
from backend.models import db

router = APIRouter(tags=["report"])


async def _load_incident(incident_id: str):
    incident = await db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No incident with id {incident_id}",
        )
    detection_rows = await db.get_incident_detections(incident_id)
    return (
        serialize_incident_row(incident),
        [serialize_detection_row(d) for d in detection_rows],
    )


@router.get("/incidents/{incident_id}/report")
async def incident_report(incident_id: str) -> Response:
    """Generate and stream a PDF report for one incident.

    404 if the incident is unknown. The filename is set from the incident id so
    a downloaded report is self-identifying in a folder of many.
    """
    incident, detections = await _load_incident(incident_id)
    pdf_bytes = build_incident_report(incident=incident, detections=detections)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="incident-{incident_id}.pdf"',
        },
    )


@router.get("/incidents/{incident_id}/stix")
async def incident_stix(incident_id: str) -> Response:
    """Generate and stream a STIX 2.1 bundle for one incident.

    See engine/stix_export.py for exactly what the bundle contains and why --
    in short, an identity, one attack-pattern per ATT&CK technique, one
    indicator per pivotable IOC already surfaced by engine/indicators.py, and
    a report object tying all of it together. 404 if the incident is unknown,
    matching the PDF endpoint above.
    """
    incident, detections = await _load_incident(incident_id)
    bundle = build_stix_bundle(incident=incident, detections=detections)

    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="incident-{incident_id}.stix.json"',
        },
    )
