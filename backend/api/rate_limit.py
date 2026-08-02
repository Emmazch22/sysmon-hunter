"""Optional rate limit for /ingest.

Single-process, in-memory -- this project runs as one collector, not a fleet
behind a load balancer, so there is no cross-instance state to coordinate and
no reason to reach for Redis just to count requests per second. The same
"off by default, opt-in via settings" shape as `auth.py`'s API-key gate: a
fresh checkout behaves exactly as it always did until an operator sets
HUNTER_INGEST_RATE_LIMIT_PER_SECOND.
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import HTTPException, Request, status

from backend.config import settings
from backend.engine.metrics import ingest_requests_total


class TokenBucket:
    """Classic token bucket: tokens refill continuously at `rate` per second,
    up to `burst` capacity; each request spends one token, or is refused.

    Continuous refill rather than a fixed window means a client sending
    exactly the configured rate never gets an artificial burst of 429s at a
    window boundary, which a naive "N requests per whole second" counter
    would produce.
    """

    def __init__(self, rate_per_second: float, burst: float) -> None:
        self.rate = rate_per_second
        self.burst = burst
        self.tokens = burst
        self._updated = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


# One bucket per source IP, created lazily on first request. Never evicted:
# a long-running server accumulates one small object per distinct client IP
# it has ever seen, which for this project's single-collector deployment
# model is a handful of entries, not a leak worth guarding against.
_buckets: dict[str, TokenBucket] = {}


def _bucket_for(client_key: str) -> TokenBucket:
    bucket = _buckets.get(client_key)
    if bucket is None or bucket.rate != settings.ingest_rate_limit_per_second:
        # Rebuilt whenever the configured rate changes (including tests that
        # monkeypatch settings mid-run) rather than only on first sight of
        # this client, so a runtime config change takes effect immediately
        # instead of only for clients not seen before the change.
        bucket = TokenBucket(
            settings.ingest_rate_limit_per_second, settings.ingest_rate_limit_burst
        )
        _buckets[client_key] = bucket
    return bucket


async def enforce_ingest_rate_limit(request: Request) -> None:
    """FastAPI dependency: 429 once a client exceeds the configured rate.

    A no-op when `HUNTER_INGEST_RATE_LIMIT_PER_SECOND` is 0 (the default) --
    the same reasoning `require_api_key` uses for an unset key.
    """
    if settings.ingest_rate_limit_per_second <= 0:
        return

    client_key = request.client.host if request.client else "unknown"
    if not _bucket_for(client_key).allow():
        ingest_requests_total.inc(outcome="rate_limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many events -- ingest rate limit exceeded",
        )
