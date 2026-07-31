"""Correlated incidents.

The endpoints an analyst actually works from. A detection is a lead; an incident
is the thing that gets triaged, and it carries the process chain and the ATT&CK
coverage that make triage possible.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status

from backend.api.serializers import serialize_detection_row, serialize_incident_row
from backend.config import settings
from backend.engine import noise as noise_engine
from backend.engine.indicators import build_indicators
from backend.models import db
from backend.models.schemas import IncidentStatus

router = APIRouter(tags=["incidents"])


def _serialize_noise(assessment: noise_engine.NoiseAssessment) -> dict[str, Any]:
    """Wire shape for a noise assessment: the strongest match's score plus the
    ranked evidence, so the console can show "why" rather than a bare number."""
    return {
        "score": assessment.score,
        "matches": [
            {"incident_id": m.incident_id, "score": m.score, "matched_on": m.matched_on}
            for m in assessment.matches
        ],
    }


async def _false_positive_history() -> list[noise_engine.Fingerprint]:
    """Every incident dismissed as a false positive, fingerprinted for
    similarity comparison.

    Recomputed per request rather than cached -- the false-positive set
    changes at analyst pace (an occasional dismissal), not request pace, so
    caching would only save an already-cheap, capped batch query. Returns an
    empty list (not an error) when nothing has been marked a false positive
    yet, which callers treat as "nothing to compare against."
    """
    rows = await db.list_incidents_by_status(IncidentStatus.FALSE_POSITIVE.value)
    if not rows:
        return []
    rule_id_map = await db.get_rule_ids_by_incident([row.id for row in rows])
    return [
        noise_engine.fingerprint_from_incident(serialize_incident_row(row), rule_id_map.get(row.id))
        for row in rows
    ]


async def _attach_noise_scores(serialized: list[dict[str, Any]]) -> None:
    """Score every *open* incident in `serialized` against the false-positive
    history, mutating each dict in place with a `noise` key.

    Only open incidents are worth scoring -- one already closed or dismissed
    has nothing left to warn an analyst about. Every incident still gets the
    key (set to `None` when there is no match or no history yet) so the
    console never has to special-case a missing field.
    """
    history = await _false_positive_history()
    open_ids = [inc["id"] for inc in serialized if inc["status"] == "open"]

    if not history or not open_ids:
        for inc in serialized:
            inc["noise"] = None
        return

    rule_id_map = await db.get_rule_ids_by_incident(open_ids)
    for inc in serialized:
        if inc["id"] not in open_ids:
            inc["noise"] = None
            continue
        candidate = noise_engine.fingerprint_from_incident(inc, rule_id_map.get(inc["id"]))
        assessment = noise_engine.assess(
            candidate, history, threshold=settings.noise_similarity_threshold
        )
        inc["noise"] = _serialize_noise(assessment) if assessment.score else None


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
    the freshest incident at the top of the queue, not the bottom. Closed
    incidents leave the live queue but stay in the database, reachable via the
    Closed view and search.
    """
    rows = await db.list_incidents(limit=limit, actionable_only=actionable_only)
    serialized = [serialize_incident_row(row) for row in rows]
    await _attach_noise_scores(serialized)
    return {
        "returned": len(serialized),
        "items": serialized,
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    """One incident with every detection that belongs to it, in the order they fired.

    This is the drill-down view: the incident summary answers "how bad", and the
    ordered detection list answers "what happened, in what sequence" -- which is
    the question that decides whether this is an intrusion or a false positive.
    """
    incident = await db.get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No incident with id {incident_id}",
        )

    detections = await db.get_incident_detections(incident_id)
    serialized = [serialize_detection_row(row) for row in detections]

    incident_dict = serialize_incident_row(incident)
    noise: Optional[dict[str, Any]] = None
    if incident_dict["status"] == "open":
        history = await _false_positive_history()
        if history:
            # The detail view already loaded every member detection above, so
            # the candidate's rule IDs come from that -- no extra query, unlike
            # the list view which has to batch-fetch them separately.
            rule_ids = {d["rule_id"] for d in serialized}
            candidate = noise_engine.fingerprint_from_incident(incident_dict, rule_ids)
            assessment = noise_engine.assess(
                candidate, history, threshold=settings.noise_similarity_threshold
            )
            noise = _serialize_noise(assessment) if assessment.score else None

    return {
        **incident_dict,
        "detections": serialized,
        "indicators": build_indicators(serialized),
        "noise": noise,
    }
