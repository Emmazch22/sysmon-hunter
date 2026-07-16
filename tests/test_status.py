"""Incident triage status.

An incident starts open. The analyst can close it, mark it a false positive,
or reopen it from any state -- the engine's upsert must never touch this
field, the same guarantee notes.py relies on.
"""

from __future__ import annotations

from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity


async def _make_incident(incident_id="s1", host="WS-01") -> None:
    inc = Incident(id=incident_id, host=host, root_guid="g")
    inc.add(
        Detection(
            rule_id="SYS-001",
            title="x",
            severity=Severity.HIGH,
            attack=["T1566.001"],
            event=Event(event_id=1),
        )
    )
    await db.upsert_incident(inc, actionable=True)


class TestStatus:
    async def test_new_incident_defaults_to_open(self, tmp_db) -> None:
        await _make_incident()
        row = (await db.list_incidents(limit=10))[0]
        assert row.status == "open"

    async def test_close_and_reopen(self, tmp_db) -> None:
        await _make_incident()
        closed = await db.update_incident_status("s1", "closed")
        assert closed.status == "closed"
        reopened = await db.update_incident_status("s1", "open")
        assert reopened.status == "open"

    async def test_mark_false_positive(self, tmp_db) -> None:
        await _make_incident()
        row = await db.update_incident_status("s1", "false_positive")
        assert row.status == "false_positive"

    async def test_engine_upsert_preserves_status(self, tmp_db) -> None:
        """The critical guarantee: a new detection landing on a closed incident
        must not silently reopen it. The engine owns score/severity; the
        analyst owns triage state."""
        await _make_incident()
        await db.update_incident_status("s1", "closed")
        inc = Incident(id="s1", host="WS-01", root_guid="g")
        inc.add(
            Detection(
                rule_id="SYS-002",
                title="y",
                severity=Severity.CRITICAL,
                attack=["T1059.001"],
                event=Event(event_id=1),
            )
        )
        await db.upsert_incident(inc, actionable=True)
        row = (await db.list_incidents(limit=10))[0]
        assert row.status == "closed"

    async def test_update_unknown_incident_returns_none(self, tmp_db) -> None:
        assert await db.update_incident_status("ghost", "closed") is None


class TestStatusEndpoint:
    async def test_set_status_ok(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("ep1")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.put("/incidents/ep1/status", json={"status": "closed"})
                assert r.status_code == 200
                assert r.json()["status"] == "closed"

    async def test_set_status_is_case_insensitive(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("ep2")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.put(
                    "/incidents/ep2/status", json={"status": "False_Positive"}
                )
                assert r.status_code == 200
                assert r.json()["status"] == "false_positive"

    async def test_set_status_rejects_unknown_value(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("ep3")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.put("/incidents/ep3/status", json={"status": "archived"})
                assert r.status_code == 422

    async def test_set_status_unknown_incident_404s(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.put("/incidents/ghost/status", json={"status": "closed"})
                assert r.status_code == 404
