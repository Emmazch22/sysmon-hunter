import logging

from fastapi import FastAPI
from fastapi.responses import FileResponse

from backend.api import detections, ingest, ws
from backend.config import BASE_DIR, settings
from backend.engine.rule_loader import rule_store

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title=settings.app_name, docs_url="/api/docs")
app.include_router(ingest.router)
app.include_router(detections.router)
app.include_router(ws.router)

DASHBOARD = BASE_DIR / "frontend" / "dashboard.html"


@app.on_event("startup")
async def startup() -> None:
    count = rule_store.load(settings.rules_dir)
    logging.getLogger(__name__).info("Motor listo con %d reglas", count)


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "rules": len(rule_store.all), "clients": ws.manager.count}