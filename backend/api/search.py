"""Search endpoint.

Backs the console's search box. Loads incidents and their detections from the
database, runs the parsed query over them, and returns matching incidents each
carrying the detections that matched -- so the UI can show why each hit matched.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi import Query as QueryParam

from backend.api.serializers import serialize_detection_row, serialize_incident_row
from backend.engine.search import parse_query, search_incidents
from backend.models import db

router = APIRouter(tags=["search"])


@router.get("/search")
async def search(
    q: str = QueryParam(
        ...,
        description="Free text and/or field filters "
        "(host:, severity:, technique:, rule:, user:, actionable:)",
    ),
    limit: int = QueryParam(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Search incidents by free text and field filters.

    Returns matching incidents, each with the detections that matched, ranked by
    number of matches. An empty or all-whitespace query returns nothing rather
    than everything -- an accidental empty search should not dump the database.
    """
    query = parse_query(q)
    if query.is_empty:
        return {
            "query": q,
            "parsed": {"text": [], "filters": {}},
            "total": 0,
            "results": [],
        }

    # Pull the incident set and every detection, then group detections by
    # incident. For the scale this tool targets (one collector) loading the set
    # and filtering in memory is simpler and fast enough; a multi-collector
    # deployment would push this into SQL.
    incident_rows = await db.list_incidents(limit=500)
    incidents = [serialize_incident_row(r) for r in incident_rows]

    detections_by_incident: dict[str, list[dict]] = {}
    for incident in incidents:
        rows = await db.get_incident_detections(incident["id"])
        detections_by_incident[incident["id"]] = [
            serialize_detection_row(r) for r in rows
        ]

    hits = search_incidents(incidents, detections_by_incident, query)[:limit]

    return {
        "query": q,
        "parsed": {"text": query.text_terms, "filters": query.filters},
        "total": len(hits),
        "results": [
            {
                "incident": hit.incident,
                "match_count": hit.match_count,
                "matched_detections": hit.matched_detections,
            }
            for hit in hits
        ],
    }
