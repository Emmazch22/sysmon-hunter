"""backend/api/rate_limit.py -- the opt-in token-bucket limiter on /ingest.

Same "off by default" contract this project already applies to the API-key
gate (see test_auth.py): a fresh checkout with HUNTER_INGEST_RATE_LIMIT_PER_SECOND
unset must behave exactly as it always did, and only once an operator sets a
rate does /ingest start returning 429s.
"""

from __future__ import annotations

import time

from httpx import ASGITransport, AsyncClient

from backend.api import rate_limit as rl
from backend.config import settings
from backend.engine.pipeline import pipeline

_EVENT = {
    "EventID": 1,
    "Computer": "LAB-WIN11",
    "Image": r"C:\Windows\System32\notepad.exe",
}


class TestTokenBucket:
    def test_allows_up_to_the_burst_then_refuses(self) -> None:
        bucket = rl.TokenBucket(rate_per_second=1, burst=3)
        assert bucket.allow() is True
        assert bucket.allow() is True
        assert bucket.allow() is True
        assert bucket.allow() is False

    def test_refills_over_time(self) -> None:
        bucket = rl.TokenBucket(rate_per_second=1000, burst=1)
        assert bucket.allow() is True
        assert bucket.allow() is False
        time.sleep(0.02)  # 1000/s refill: ~20 tokens accrue in 20ms
        assert bucket.allow() is True

    def test_never_exceeds_burst_capacity(self) -> None:
        bucket = rl.TokenBucket(rate_per_second=1000, burst=2)
        time.sleep(0.05)  # would refill well past 2 tokens if uncapped
        used = 0
        while bucket.allow():
            used += 1
        assert used == 2


class TestEnforceIngestRateLimit:
    async def test_disabled_by_default_never_limits(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "ingest_rate_limit_per_second", 0)
        rl._buckets.clear()
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                for _ in range(20):
                    r = await c.post("/ingest", json=_EVENT)
                    assert r.status_code == 202

    async def test_exceeding_the_configured_rate_returns_429(
        self, tmp_db, monkeypatch
    ) -> None:
        monkeypatch.setattr(settings, "ingest_rate_limit_per_second", 1)
        monkeypatch.setattr(settings, "ingest_rate_limit_burst", 2)
        rl._buckets.clear()
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                statuses = [
                    (await c.post("/ingest", json=_EVENT)).status_code
                    for _ in range(4)
                ]
                assert statuses[:2] == [202, 202]
                assert 429 in statuses[2:]

    async def test_recovers_once_disabled_again(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "ingest_rate_limit_per_second", 1)
        monkeypatch.setattr(settings, "ingest_rate_limit_burst", 1)
        rl._buckets.clear()
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                await c.post("/ingest", json=_EVENT)
                assert (await c.post("/ingest", json=_EVENT)).status_code == 429

                # Config change mid-run (e.g. an operator turning it back off)
                # takes effect immediately -- _bucket_for rebuilds on rate change.
                monkeypatch.setattr(settings, "ingest_rate_limit_per_second", 0)
                assert (await c.post("/ingest", json=_EVENT)).status_code == 202
