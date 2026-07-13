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

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api import (
    attack,
    detections,
    enrich,
    incidents,
    ingest,
    report,
    search,
    ws,
)
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
    version="0.2.0",
    lifespan=lifespan,
    # The root path belongs to the analyst, not to Swagger.
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.include_router(ingest.router)
app.include_router(detections.router)
app.include_router(incidents.router)
app.include_router(ws.router)
app.include_router(attack.router)
app.include_router(enrich.router)
app.include_router(report.router)
app.include_router(search.router)

# Serve the console's CSS and JS. Split out of the HTML so each is cached and
# edited on its own, rather than shipping one monolithic file.
app.mount("/static", StaticFiles(directory=str(FRONTEND / "static")), name="static")


@app.get("/", include_in_schema=False)
async def console() -> FileResponse:
    """Serve the analyst console."""
    return FileResponse(CONSOLE)


@app.get("/incident/{incident_id}", include_in_schema=False)
async def incident_page(incident_id: str) -> FileResponse:
    """Serve the full-page incident view. The page reads the id from the URL and
    fetches the incident client-side, so the same static file serves any id."""
    return FileResponse(FRONTEND / "incident.html")


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
