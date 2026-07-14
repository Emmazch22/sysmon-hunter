"""Incident notes.

A free-text note attached to an incident, editable from its full-page view. The
note belongs to the analyst: the engine's upsert must never overwrite it, and it
persists until explicitly changed or deleted.
"""

from __future__ import annotations

from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity


async def _make_incident(incident_id="n1", host="WS-01") -> None:
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


class TestNotes:
    async def test_set_and_read_note(self, tmp_db) -> None:
        await _make_incident()
        row = await db.update_incident_notes("n1", "Confirmed credential theft.")
        assert row.notes == "Confirmed credential theft."

    async def test_delete_note_clears_it(self, tmp_db) -> None:
        await _make_incident()
        await db.update_incident_notes("n1", "temp note")
        row = await db.update_incident_notes("n1", "")
        assert row.notes == ""

    async def test_engine_upsert_preserves_the_note(self, tmp_db) -> None:
        """The critical guarantee: a new detection on an incident must not wipe
        the analyst's note. The engine owns score/severity; the analyst owns the
        note."""
        await _make_incident()
        await db.update_incident_notes("n1", "important analysis")
        # engine re-upserts (a new detection landed)
        inc = Incident(id="n1", host="WS-01", root_guid="g")
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
        assert row.notes == "important analysis"

    async def test_update_unknown_incident_returns_none(self, tmp_db) -> None:
        assert await db.update_incident_notes("ghost", "x") is None


class TestNotesEndpoint:
    async def test_word_limit_enforced(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("ep1")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                over = " ".join(["word"] * 501)
                r = await c.put("/incidents/ep1/notes", json={"notes": over})
                assert r.status_code == 422
                ok = await c.put("/incidents/ep1/notes", json={"notes": "short note"})
                assert ok.status_code == 200

    async def test_delete_endpoint(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("ep2")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                await c.put("/incidents/ep2/notes", json={"notes": "to be deleted"})
                r = await c.delete("/incidents/ep2/notes")
                assert r.status_code == 200
                assert r.json()["notes"] == ""
