"""Detection history.

Read-only. Detections are evidence: the API can serve them and nothing else can
touch them.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from backend.api.serializers import serialize_detection_row
from backend.models import db

router = APIRouter(tags=["detections"])


@router.get("/detections")
async def list_detections(
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Most recent detections, oldest first.

    Ordered oldest-first because the console appends downward, so the newest
    detection lands at the bottom of the feed exactly where a live push would
    have put it. Reversing here rather than in JavaScript keeps the two paths
    identical.
    """
    rows = await db.list_detections(limit=limit)
    total = await db.count_detections()
    return {
        "total": total,
        "returned": len(rows),
        "items": [serialize_detection_row(row) for row in rows],
    }