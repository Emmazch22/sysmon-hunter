"""Aggregate stats for the console's dashboard page.

Read-only, so the surface is a single GET, same shape as `attack.py`'s
coverage endpoints -- the route stays thin and hands off to
`engine/stats.py` for the actual aggregation.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from backend.engine.stats import DEFAULT_DAYS, MAX_DAYS, build_stats

router = APIRouter(tags=["stats"])


@router.get("/stats")
async def get_stats(
    days: int = Query(DEFAULT_DAYS, ge=1, le=MAX_DAYS),
) -> dict[str, Any]:
    """Incidents-per-day (last `days`, zero-filled), severity distribution,
    triage totals, and the top rules/ATT&CK techniques by detection count --
    across every incident and detection on record.
    """
    return await build_stats(days=days)
