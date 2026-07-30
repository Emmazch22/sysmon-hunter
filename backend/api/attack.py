"""ATT&CK technique endpoint.

Backs the clickable technique chips in the console. Read-only reference data, so
the surface is a single GET.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Response, status

from backend.engine.attack import attack_lookup
from backend.engine.coverage import build_navigator_layer, build_report

router = APIRouter(tags=["attack"])


@router.get("/attack/coverage")
async def get_coverage_report() -> dict[str, Any]:
    """The rule-coverage report: every ATT&CK technique this project can
    detect, plus -- when `backend/data/attack_index.json` is present -- every
    technique it cannot. See `engine/coverage.py` for the partial-vs-full
    distinction.

    Declared ahead of `/attack/{technique_id}` deliberately: both match the
    single path segment "coverage", and FastAPI resolves path collisions in
    registration order, so this route would be shadowed by the catch-all
    technique lookup (returning a 404 "No ATT&CK data for coverage") if the
    order were reversed.
    """
    return build_report()


@router.get("/attack/coverage/navigator")
async def get_coverage_navigator_layer() -> Response:
    """The same coverage report, rendered as a MITRE ATT&CK Navigator layer
    (v4.5) and offered as a download. Drop the file at
    https://mitre-attack.github.io/attack-navigator/ to see every technique
    colored by how many rules/detectors raise it -- red is a gap, green is
    well covered.
    """
    layer = build_navigator_layer()
    return Response(
        content=json.dumps(layer, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="sysmon-hunter-coverage.navigator.json"'
        },
    )


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
