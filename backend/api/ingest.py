"""Telemetry intake.

The single door every event comes through, whatever produced it: Winlogbeat on a
live endpoint, the EVTX replay script, or a hand-written request during rule
development.

Deliberately thin. All it does is hand the payload to the pipeline -- the moment
detection logic starts leaking into a route handler, it stops being testable
without an HTTP client.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status

from backend.engine import metrics
from backend.engine.pipeline import pipeline

log = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest(payload: dict[str, Any]) -> dict[str, Any]:
    """Accept one Sysmon event and run it through the detection pipeline.

    Returns 202 rather than 200: the event has been accepted and evaluated, but
    the collector should not read anything into the response beyond that. It is
    a shipper, not an analyst -- if it starts making decisions based on whether
    we raised a detection, the detection logic has escaped the server.

    A malformed payload returns 400 and is dropped. It is never retried, because
    a collector that retries a payload we cannot parse will retry it forever.
    """
    try:
        result = await pipeline.process(payload)
    except Exception as exc:  # noqa: BLE001 - the boundary must not leak stack traces
        log.exception("Failed to process inbound event")
        metrics.ingest_requests_total.inc(outcome="malformed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed event payload: {exc}",
        ) from exc
    metrics.ingest_requests_total.inc(outcome="accepted")
    return result