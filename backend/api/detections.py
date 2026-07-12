from fastapi import APIRouter

from backend.api.ingest import DETECTIONS

router = APIRouter(tags=["detections"])


@router.get("/detections")
async def list_detections(limit: int = 100) -> dict:
    items = DETECTIONS[-limit:]
    return {
        "total": len(DETECTIONS),
        "items": [
            {
                "rule_id": d.rule_id,
                "title": d.title,
                "severity": d.severity,
                "attack": d.attack,
                "host": d.event.host,
                "image": d.event.image,
                "command_line": d.event.command_line,
                "matched_at": d.matched_at,
            }
            for d in items
        ],
    }