"""Administrative actions.

A single destructive action lives here today: wiping the database. Kept in
its own router, tagged distinctly from the read/write endpoints an analyst
reaches for moment to moment, so it is easy to find -- and easy to lock down
or remove -- independently of everything else.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from backend.api.ws import manager
from backend.engine.pipeline import pipeline
from backend.models import db

log = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])


@router.delete("/admin/database")
async def reset_database() -> dict[str, Any]:
    """Wipe every detection and incident, and reset the live engine to match.

    Two things have to happen together, in this order: the persisted rows go
    first, then the in-memory process tree and detectors are rebuilt from
    scratch (see Pipeline.reset). Skipping the second half would leave the
    engine correlating new events against a tree that remembers incidents the
    database no longer has any record of.

    Every connected console is notified over the websocket, not just the tab
    that clicked the button -- this is a shared live view, and a reset that
    only one analyst's screen reflects is worse than no reset at all.
    """
    await db.reset_database()
    pipeline.reset()
    await manager.broadcast({"type": "reset", "data": {}})

    log.warning("Database reset via /admin/database")
    return {"status": "reset"}
