import logging

from fastapi import FastAPI

from backend.api import detections, ingest
from backend.config import settings
from backend.engine.rule_loader import rule_store

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title=settings.app_name)
app.include_router(ingest.router)
app.include_router(detections.router)


@app.on_event("startup")
async def startup() -> None:
    count = rule_store.load(settings.rules_dir)
    logging.getLogger(__name__).info("Motor listo con %d reglas", count)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "rules": len(rule_store.all)}