from fastapi import APIRouter

from backend.engine.matcher import evaluate
from backend.engine.normalizer import normalize
from backend.engine.rule_loader import rule_store

router = APIRouter(tags=["ingest"])

# store en memoria por ahora; en el siguiente paso pasa a SQLite
DETECTIONS: list = []


@router.post("/ingest")
async def ingest(payload: dict) -> dict:
    event = normalize(payload)
    rules = rule_store.for_event(event.event_id)
    hits = evaluate(event, rules)
    DETECTIONS.extend(hits)
    return {
        "event_id": event.event_id,
        "rules_evaluated": len(rules),
        "detections": [{"rule_id": d.rule_id, "title": d.title, "severity": d.severity} for d in hits],
    }