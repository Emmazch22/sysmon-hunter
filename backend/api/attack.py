"""ATT&CK technique endpoint.

Backs the clickable technique chips in the console. Read-only reference data, so
the surface is a single GET.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from backend.engine.attack import attack_lookup

router = APIRouter(tags=["attack"])


@router.get("/attack/{technique_id}")
async def get_technique(technique_id: str) -> dict[str, Any]:
    """Return one ATT&CK technique's name, description, tactics and MITRE URL.

    404 if the technique is unknown -- which, given the chips are generated from
    the same corpus that seeds the lookup, should only happen for a
    sub-technique whose parent is also absent.
    """
    technique = attack_lookup.get(technique_id.upper())
    if technique is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ATT&CK data for {technique_id}",
        )
    return technique
