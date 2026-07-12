from typing import Any

from fastapi import APIRouter

from backend.models.schemas import Detection

router = APIRouter(tags=["detections"])

DETECTIONS: list[Detection] = []


def serialize(d: Detection) -> dict[str, Any]:
    """Forma unica compartida por REST y WebSocket."""
    return {
        "rule_id": d.rule_id,
        "title": d.title,
        "severity": d.severity.value,
        "attack": d.attack,
        "host": d.event.host,
        "image": d.event.image,
        "parent_image": d.event.parent_image,
        "command_line": d.event.command_line,
        "matched_at": d.matched_at.isoformat(),
    }


@router.get("/detections")
async def list_detections(limit: int = 100) -> dict:
    items = DETECTIONS[-limit:]
    return {"total": len(DETECTIONS), "items": [serialize(d) for d in items]}