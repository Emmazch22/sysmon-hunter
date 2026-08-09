"""Telemetry intake.

The single door every event comes through, whatever produced it: Winlogbeat on a
live endpoint, the EVTX replay script, or a hand-written request during rule
development.

Deliberately thin. All it does is hand the payload to the pipeline -- the moment
detection logic starts leaking into a route handler, it stops being testable
without an HTTP client.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from backend.engine import metrics
from backend.engine.pipeline import pipeline

log = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])

# A single Sysmon/Winlogbeat event, even a verbose one with a long command
# line and several hashes, comfortably fits in a few KB. A megabyte is
# generous headroom above that -- big enough that no real event ever brushes
# up against it, small enough that a hostile or malfunctioning sender POSTing
# an unbounded body cannot use this, the one endpoint built to accept
# external input at volume, to exhaust server memory.
MAX_EVENT_BYTES = 1_000_000


async def _read_bounded_body(request: Request) -> bytes:
    """Read the request body while enforcing MAX_EVENT_BYTES against the
    bytes actually received, not against the Content-Length header.

    Content-Length is a useful fast-path rejection when present, but it is
    the sender's word for its own body size -- absent under chunked transfer
    encoding, and not something this endpoint should trust as the *only*
    check. Streaming the body and counting as it arrives is what actually
    bounds memory regardless of what the client claims.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_EVENT_BYTES:
                raise HTTPException(
                    status.HTTP_413_CONTENT_TOO_LARGE,
                    f"Event payload exceeds the {MAX_EVENT_BYTES}-byte limit",
                )
        except ValueError:
            pass  # not a valid integer -- fall through to the streaming check

    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > MAX_EVENT_BYTES:
            raise HTTPException(
                status.HTTP_413_CONTENT_TOO_LARGE,
                f"Event payload exceeds the {MAX_EVENT_BYTES}-byte limit",
            )
    return bytes(chunks)


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest(request: Request) -> dict[str, Any]:
    """Accept one Sysmon event and run it through the detection pipeline.

    Returns 202 rather than 200: the event has been accepted and evaluated, but
    the collector should not read anything into the response beyond that. It is
    a shipper, not an analyst -- if it starts making decisions based on whether
    we raised a detection, the detection logic has escaped the server.

    A malformed payload returns 400 and is dropped. It is never retried, because
    a collector that retries a payload we cannot parse will retry it forever.

    Takes the raw `Request` rather than a `payload: dict[str, Any]` parameter
    so the body can be read through `_read_bounded_body` -- FastAPI's usual
    automatic body parsing buffers the whole body into memory before this
    function ever runs, which is exactly the unbounded read a size cap has to
    happen ahead of, not after.
    """
    body = await _read_bounded_body(request)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        metrics.ingest_requests_total.inc(outcome="malformed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed JSON body: {exc}",
        ) from exc

    if not isinstance(payload, dict):
        metrics.ingest_requests_total.inc(outcome="malformed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Event payload must be a JSON object",
        )

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