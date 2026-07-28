"""The optional X-API-Key gate (backend/api/auth.py).

Two things must both be true: with no key configured (the out-of-the-box
default), the API stays exactly as open as it always was -- nothing about
this feature should surprise a fresh checkout. And once HUNTER_API_KEY is
set, every gated router actually enforces it, since a "protection" that
silently no-ops on some endpoints is worse than none at all.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from backend.config import settings
from backend.engine.pipeline import pipeline


class TestApiKeyUnset:
    async def test_gated_endpoint_works_with_no_key_configured(self, tmp_db) -> None:
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents")
                assert r.status_code == 200


class TestApiKeyEnforced:
    async def test_missing_header_is_rejected(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "s3cret")
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents")
                assert r.status_code == 401

    async def test_wrong_key_is_rejected(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "s3cret")
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents", headers={"X-API-Key": "wrong"})
                assert r.status_code == 401

    async def test_correct_key_is_accepted(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "s3cret")
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents", headers={"X-API-Key": "s3cret"})
                assert r.status_code == 200

    async def test_page_routes_stay_open(self, tmp_db, monkeypatch) -> None:
        """/, /health, and the incident/tree pages are not JSON API routers --
        they're plain routes on the app, never wrapped with the dependency,
        so the console itself keeps loading even with a key configured."""
        monkeypatch.setattr(settings, "api_key", "s3cret")
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                assert (await c.get("/")).status_code == 200
                assert (await c.get("/health")).status_code == 200
                assert (await c.get("/incident/x")).status_code == 200
