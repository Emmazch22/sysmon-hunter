from fastapi import APIRouter

from backend.api.detections import DETECTIONS, serialize
from backend.api.ws import manager
from backend.engine.matcher import evaluate
from backend.engine.normalizer import normalize
from backend.engine.rule_loader import rule_store

router = APIRouter(tags=["ingest"])


@router.post("/ingest")
async def ingest(payload: dict) -> dict:
    event = normalize(payload)
    rules = rule_store.for_event(event.event_id)
    hits = evaluate(event, rules)

    for d in hits:
        DETECTIONS.append(d)
        await manager.broadcast({"type": "detection", "data": serialize(d)})

    return {
        "event_id": event.event_id,
        "rules_evaluated": len(rules),
        "detections": [
            {"rule_id": d.rule_id, "title": d.title, "severity": d.severity} for d in hits
        ],
    }