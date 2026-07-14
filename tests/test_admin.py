"""Database reset.

A single destructive admin action, reachable from the console's settings
dropdown: wipe every detection and incident. Two guarantees matter here --
the tables actually empty out, and the live pipeline's in-memory state (the
process tree, the correlation engine, the beacon/discovery detectors) is
rebuilt alongside them, so the engine never correlates a new event against a
tree that remembers an incident the database no longer has.
"""

from __future__ import annotations

from backend.engine.pipeline import pipeline
from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity


async def _make_incident(incident_id="a1", host="WS-01") -> None:
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
    await db.save_detection(inc.detections[0])


class TestResetDatabase:
    async def test_reset_clears_detections_and_incidents(self, tmp_db) -> None:
        await _make_incident()
        assert await db.count_detections() == 1
        assert len(await db.list_incidents()) == 1

        await db.reset_database()

        assert await db.count_detections() == 0
        assert await db.list_incidents() == []

    async def test_pipeline_reset_rebuilds_live_state(self) -> None:
        event = Event(event_id=1, host="WS-01", process_guid="g1")
        pipeline.tree.observe(event)
        assert pipeline.tree.size > 0
        pipeline._events_seen = 42

        pipeline.reset()

        assert pipeline.tree.size == 0
        assert pipeline._events_seen == 0
        assert pipeline.incidents.open_count == 0


class TestResetEndpoint:
    async def test_delete_admin_database(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        await _make_incident("ep1")
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.delete("/admin/database")
                assert r.status_code == 200
                assert r.json()["status"] == "reset"
                assert await db.count_detections() == 0
                assert await db.list_incidents() == []
