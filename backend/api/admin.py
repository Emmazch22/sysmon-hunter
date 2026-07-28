"""Administrative actions.

A destructive action (wiping the database) and the runtime settings an
analyst can flip live from the console -- currently just the behavioral
baseline toggle. Kept in its own router, tagged distinctly from the
read/write endpoints an analyst reaches for moment to moment, so it is easy
to find -- and easy to lock down or remove -- independently of everything
else.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from backend.api.ws import manager
from backend.engine.pipeline import pipeline
from backend.engine.runtime_settings import runtime_settings
from backend.models import db

log = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])


class SettingsUpdate(BaseModel):
    behavior_baseline_enabled: bool


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


@router.get("/admin/settings")
async def get_settings() -> dict[str, bool]:
    """Current value of every runtime-editable setting.

    Read by the console on load, so a toggle flipped from one analyst's tab
    shows correctly the next time any tab (re)opens the settings menu.
    """
    return runtime_settings.as_dict()


@router.put("/admin/settings")
async def update_settings(update: SettingsUpdate) -> dict[str, bool]:
    """Flip a runtime setting, effective immediately for this process and
    persisted for the next one.

    Broadcast over the websocket like the database reset above -- if one
    analyst turns the baseline detector on, every open console should reflect
    that, not just the tab that clicked it.
    """
    await runtime_settings.set_behavior_baseline_enabled(
        update.behavior_baseline_enabled
    )
    payload = runtime_settings.as_dict()
    await manager.broadcast({"type": "settings", "data": payload})
    return payload
