"""Application entrypoint.

Wires the routers, boots the database and rule set, and runs the housekeeping
loop that keeps the in-memory process tree from growing without bound.

Run with:
    python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Console:  http://localhost:8000
API docs: http://localhost:8000/api/docs
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.api import (
    admin,
    attack,
    detections,
    enrich,
    incidents,
    ingest,
    notes,
    profile,
    report,
    search,
    status,
    ws,
)
from backend.api.auth import require_api_key
from backend.config import BASE_DIR, settings
from backend.engine.attack import attack_lookup
from backend.engine.enrichment import enrichment_service
from backend.engine.pipeline import pipeline
from backend.engine.rule_loader import rule_store
from backend.models import db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hunter")

FRONTEND = BASE_DIR / "frontend"
CONSOLE = FRONTEND / "console.html"

# How often the background loop closes idle incidents and evicts dead processes.
# Well under the correlation window, so an incident is never held open by
# nothing more than the sweeper not having run yet.
SWEEP_INTERVAL_SECONDS = 60


async def _sweep_loop() -> None:
    """Periodic housekeeping for the correlation engine.

    Runs for the life of the app. Any error is logged and the loop continues:
    a failed sweep means the tree is briefly larger than it should be, which is
    a memory concern, not a correctness one. Killing the loop over it would turn
    a leak into an outage.
    """
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        try:
            pruned = pipeline.sweep()
            if pruned:
                log.debug("Sweep evicted %d process nodes", pruned)
        except Exception:  # noqa: BLE001
            log.exception("Sweep failed, continuing")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start and stop the engine alongside the server."""
    await db.init_db()

    count = rule_store.load(settings.rules_dir)
    attack_lookup.load()
    if rule_store.errors:
        log.warning("%d rule(s) were rejected -- see /health", len(rule_store.errors))
    if count == 0:
        log.warning(
            "No rules loaded. The engine will accept events and detect nothing."
        )

    sweeper = asyncio.create_task(_sweep_loop())
    log.info("%s ready with %d rules", settings.app_name, count)

    yield

    sweeper.cancel()
    log.info("Engine stopped")


app = FastAPI(
    title=settings.app_name,
    description="Sysmon detection engine with process-tree correlation.",
    version="0.3.3",
    lifespan=lifespan,
    # The root path belongs to the analyst, not to Swagger.
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Every JSON API router is gated by the optional API-key dependency (see
# backend/api/auth.py) -- a no-op unless HUNTER_API_KEY is set. ws.router is
# deliberately excluded: browsers cannot attach custom headers to a
# WebSocket handshake, so there is no way for require_api_key to see the key
# on that connection. The console falling back to polling if the socket is
# ever actually locked down is a gap worth knowing about, not one this
# dependency can close.
_api_key_gate = [Depends(require_api_key)]
app.include_router(ingest.router, dependencies=_api_key_gate)
app.include_router(detections.router, dependencies=_api_key_gate)
app.include_router(incidents.router, dependencies=_api_key_gate)
app.include_router(ws.router)
app.include_router(attack.router, dependencies=_api_key_gate)
app.include_router(enrich.router, dependencies=_api_key_gate)
app.include_router(report.router, dependencies=_api_key_gate)
app.include_router(search.router, dependencies=_api_key_gate)
app.include_router(profile.router, dependencies=_api_key_gate)
app.include_router(notes.router, dependencies=_api_key_gate)
app.include_router(status.router, dependencies=_api_key_gate)
app.include_router(admin.router, dependencies=_api_key_gate)

# Serve the console's CSS and JS. Split out of the HTML so each is cached and
# edited on its own, rather than shipping one monolithic file.
app.mount("/static", StaticFiles(directory=str(FRONTEND / "static")), name="static")


@app.get("/", include_in_schema=False)
async def console() -> FileResponse:
    """Serve the analyst console."""
    return FileResponse(CONSOLE)


_FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="6" fill="#0B0F14"/>'
    '<path d="M16 4l9 3.5v7c0 5.8-3.9 9.6-9 11.5-5.1-1.9-9-5.7-9-11.5v-7L16 4z" '
    'fill="none" stroke="#3FB6C8" stroke-width="2" stroke-linejoin="round"/>'
    '<circle cx="16" cy="15" r="2.5" fill="#3FB6C8"/>'
    '<path d="M16 17.5v4" stroke="#3FB6C8" stroke-width="2" stroke-linecap="round"/></svg>'
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    """Serve the shield favicon as SVG, so browsers stop 404-ing on /favicon.ico."""
    return Response(content=_FAVICON, media_type="image/svg+xml")


@app.get("/incident/{incident_id}", include_in_schema=False)
async def incident_page(incident_id: str) -> FileResponse:
    """Serve the full-page incident view. The page reads the id from the URL and
    fetches the incident client-side, so the same static file serves any id."""
    return FileResponse(FRONTEND / "incident.html")


@app.get("/incident/{incident_id}/explore", include_in_schema=False)
async def incident_explore_page(incident_id: str) -> FileResponse:
    """Serve the full-screen explorer: a pannable/zoomable process tree or
    timeline, picked with ?view=tree|timeline (default tree) and switchable
    from tabs in the page itself.

    Same pattern as /incident/{id}: a static page that reads the id from the
    URL and fetches the incident client-side. Split into its own route (rather
    than a mode toggle on the incident page) because it wants the whole
    viewport for panning and zooming, which a page carrying the summary,
    indicators, and notes editor cannot spare."""
    return FileResponse(FRONTEND / "tree.html")


@app.get("/incident/{incident_id}/tree", include_in_schema=False)
async def incident_tree_page(incident_id: str) -> FileResponse:
    """Alias for /explore?view=tree, kept for old links and bookmarks."""
    return FileResponse(FRONTEND / "tree.html")


@app.get("/health", tags=["ops"])
async def health() -> dict[str, Any]:
    """Engine status.

    Reports rejected rules explicitly. A rule that failed to load is a blind
    spot, and a blind spot that nothing reports is the worst kind -- so it is
    surfaced here rather than left in a log line nobody reads.
    """
    return {
        "status": "ok",
        "consoles_connected": ws.manager.count,
        "rule_errors": rule_store.errors,
        "enrichment_providers": enrichment_service.providers_configured,
        "coverage_by_event_id": rule_store.coverage,
        **pipeline.stats,
    }
