"""Incident triage: status, classification, notes.

The SOC workflow layered on top of detection. These tests pin the two rules that
matter: the engine's upsert must never overwrite the analyst's fields, and a
closed incident leaves the live queue but stays in the database.
"""

from __future__ import annotations

import pytest

from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity


async def _make_incident(incident_id="tri1", host="WS-01") -> None:
    """Persist a minimal incident to triage against."""
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


class TestTriageUpdate:
    async def test_set_status_classification_notes(self, tmp_db) -> None:
        await _make_incident()
        row = await db.update_incident_triage(
            "tri1", status="in_progress", classification="tp", notes="Escalated to IR."
        )
        assert row.status == "in_progress"
        assert row.classification == "tp"
        assert row.notes == "Escalated to IR."

    async def test_partial_update_leaves_other_fields(self, tmp_db) -> None:
        """A PATCH of one field must not reset the others -- setting a note after
        classifying must not wipe the classification."""
        await _make_incident()
        await db.update_incident_triage("tri1", classification="fp")
        await db.update_incident_triage("tri1", notes="benign admin activity")
        row = (await db.list_incidents(limit=10, status=None))[0]
        assert row.classification == "fp"  # survived the notes update
        assert row.notes == "benign admin activity"

    async def test_engine_upsert_does_not_reset_triage(self, tmp_db) -> None:
        """The critical guarantee: a new detection arriving on an already-triaged
        incident must not revert the analyst's status back to 'new'. The engine
        owns score/severity; the analyst owns status/classification/notes."""
        await _make_incident()
        await db.update_incident_triage(
            "tri1", status="in_progress", classification="tp"
        )

        # A later detection re-runs upsert_incident on the same id.
        inc = Incident(id="tri1", host="WS-01", root_guid="g")
        inc.add(
            Detection(
                rule_id="SYS-041",
                title="y",
                severity=Severity.CRITICAL,
                attack=["T1003.001"],
                event=Event(event_id=10),
            )
        )
        await db.upsert_incident(inc, actionable=True)

        row = (await db.list_incidents(limit=10))[0]
        assert row.status == "in_progress"  # NOT reset to "new"
        assert row.classification == "tp"

    async def test_update_unknown_incident_returns_none(self, tmp_db) -> None:
        assert await db.update_incident_triage("nope", status="closed") is None


class TestQueueFiltering:
    async def test_closed_leaves_open_queue_but_stays_in_db(self, tmp_db) -> None:
        await _make_incident("open1")
        await _make_incident("done1")
        await db.update_incident_triage("done1", status="closed")

        open_rows = await db.list_incidents(limit=50, exclude_status="closed")
        closed_rows = await db.list_incidents(limit=50, status="closed")

        assert {r.id for r in open_rows} == {"open1"}
        assert {r.id for r in closed_rows} == {"done1"}


class TestNotesLimit:
    """Notes are a summary, not a report: 500 words is the ceiling."""

    async def test_notes_over_limit_rejected(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("noteinc")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                over = " ".join(["word"] * 501)
                r = await c.patch("/incidents/noteinc/triage", json={"notes": over})
                assert r.status_code == 422
                assert "500" in r.json()["detail"]

    async def test_notes_at_limit_accepted(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("noteinc2")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                exactly = " ".join(["word"] * 500)
                r = await c.patch("/incidents/noteinc2/triage", json={"notes": exactly})
                assert r.status_code == 200
