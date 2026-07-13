"""IOC enrichment endpoint.

Backs the "enrich" action in the console. An analyst looking at a beacon
incident clicks to pull reputation on its destination, and this returns what the
configured providers know.

Enrichment is a deliberate, on-demand action, not something that happens to
every event -- see engine/enrichment.py for why. So it is a plain GET the UI
calls when the analyst asks, and nothing calls it automatically.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from backend.engine.enrichment import enrichment_service

router = APIRouter(tags=["enrichment"])


@router.get("/enrich")
async def enrich(
    indicator: str = Query(..., description="An IP address or domain to look up."),
) -> dict[str, Any]:
    """Return reputation for one indicator across the configured providers.

    422 if the indicator is not something we enrich (a private IP, or a value
    that is neither an IP nor a domain) -- so the UI can tell the difference
    between "nothing known" and "not a valid target".
    """
    result = await enrichment_service.enrich(indicator)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{indicator!r} is not a public IP or domain that can be enriched.",
        )

    return {
        "indicator": result.indicator,
        "type": result.indicator_type,
        "worst_verdict": result.worst_verdict,
        "providers": [
            {
                "provider": r.provider,
                "available": r.available,
                "verdict": r.verdict,
                "summary": r.summary,
                "details": r.details,
                "link": r.link,
            }
            for r in result.results
        ],
    }
