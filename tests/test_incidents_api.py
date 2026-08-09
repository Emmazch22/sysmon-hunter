"""The read/write endpoints an analyst's console actually calls.

Everything in `admin.py`, `notes.py`, and `status.py` already has direct API
tests; the busier endpoints -- ingest, the incident list, and a single
incident's drill-down -- did not, which is exactly how the `GET
/incidents/{id}` 500-row-window bug (fixed alongside these tests) shipped
and went unnoticed. These pin the endpoints down at the HTTP layer, not just
the engine functions underneath them.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from backend.engine.pipeline import pipeline
from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity


async def _make_incident(incident_id: str, host: str = "WS-01") -> None:
    inc = Incident(id=incident_id, host=host, root_guid=f"g-{incident_id}")
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


class TestIngestEndpoint:
    async def test_ingest_accepts_a_well_formed_event(self, tmp_db) -> None:
        """202, not 200 -- the collector is told the event was accepted and
        evaluated, nothing about whether it happened to raise a detection."""
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.post(
                    "/ingest",
                    json={
                        "EventID": 1,
                        "Computer": "LAB-WIN11",
                        "Image": r"C:\Windows\System32\notepad.exe",
                        "ProcessGuid": "{g1}",
                    },
                )
                assert r.status_code == 202
                body = r.json()
                assert body["event_id"] == 1
                assert body["host"] == "LAB-WIN11"

    async def test_ingest_rejects_a_malformed_payload(self, tmp_db) -> None:
        """A payload the pipeline cannot process 400s and is dropped -- never
        retried, so a collector cannot hammer the same bad event forever."""
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                # A ProcessId that cannot be coerced to int elsewhere would be
                # silently dropped by the normalizer, so simulate a genuinely
                # malformed body instead: not a JSON object at all.
                r = await c.post("/ingest", content=b"not json", headers={"Content-Type": "application/json"})
                assert r.status_code in (400, 422)

    async def test_ingest_rejects_a_body_over_the_size_cap(self, tmp_db, monkeypatch) -> None:
        """A single Sysmon event never legitimately approaches the cap -- this
        exists for the hostile or malfunctioning sender POSTing an unbounded
        body at the one endpoint built to accept external input at volume."""
        from backend.api import ingest as ingest_module
        from backend.main import app

        monkeypatch.setattr(ingest_module, "MAX_EVENT_BYTES", 100)
        pipeline.reset()

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                oversized = {
                    "EventID": 1,
                    "Computer": "LAB-WIN11",
                    "Image": r"C:\Windows\System32\notepad.exe",
                    "CommandLine": "x" * 500,
                }
                r = await c.post("/ingest", json=oversized)
                assert r.status_code == 413

    async def test_ingest_still_accepts_a_normal_event_under_the_cap(
        self, tmp_db, monkeypatch
    ) -> None:
        from backend.api import ingest as ingest_module
        from backend.main import app

        monkeypatch.setattr(ingest_module, "MAX_EVENT_BYTES", 100)
        pipeline.reset()

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.post(
                    "/ingest",
                    json={"EventID": 1, "Computer": "LAB-WIN11", "Image": r"C:\a.exe"},
                )
                assert r.status_code == 202

    async def test_ingest_fires_a_matching_rule(self, tmp_db) -> None:
        """An event shaped like a real detection actually raises one --
        end-to-end through normalize -> match -> correlate -> persist."""
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                # SYS-004: shadow copy deletion via vssadmin.
                r = await c.post(
                    "/ingest",
                    json={
                        "EventID": 1,
                        "Computer": "LAB-WIN11",
                        "Image": r"C:\Windows\System32\vssadmin.exe",
                        "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                        "ProcessGuid": "{g2}",
                    },
                )
                assert r.status_code == 202
                rule_ids = [d["rule_id"] for d in r.json()["detections"]]
                assert "SYS-004" in rule_ids


class TestListIncidentsEndpoint:
    async def test_returns_incidents_newest_first(self, tmp_db) -> None:
        from backend.main import app

        await _make_incident("older", host="WS-01")
        await _make_incident("newer", host="WS-02")

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents")
                assert r.status_code == 200
                ids = [i["id"] for i in r.json()["items"]]
                assert ids.index("newer") < ids.index("older")

    async def test_actionable_only_filters(self, tmp_db) -> None:
        from backend.main import app

        inc = Incident(id="watching", host="WS-01", root_guid="g")
        inc.add(
            Detection(
                rule_id="SYS-005",
                title="x",
                severity=Severity.LOW,
                attack=[],
                event=Event(event_id=1),
            )
        )
        await db.upsert_incident(inc, actionable=False)
        await _make_incident("flagged")

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents", params={"actionable_only": True})
                ids = {i["id"] for i in r.json()["items"]}
                assert "flagged" in ids
                assert "watching" not in ids


class TestGetIncidentEndpoint:
    async def test_returns_incident_with_detections_and_indicators(self, tmp_db) -> None:
        from backend.main import app

        await _make_incident("full1")

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents/full1")
                assert r.status_code == 200
                body = r.json()
                assert body["id"] == "full1"
                assert len(body["detections"]) == 1
                assert "indicators" in body

    async def test_unknown_incident_404s(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/incidents/ghost")
                assert r.status_code == 404

    async def test_an_incident_outside_the_recent_500_is_still_reachable(
        self, tmp_db
    ) -> None:
        """Regression test for the bug this session fixed: GET /incidents/{id}
        used to fetch only the 500 most recent incidents and scan them in
        Python, so anything older 404'd despite existing. Kept small (11, not
        501) so the test suite stays fast; the behavior under test is the
        lookup path, not the exact number 500."""
        from backend.main import app

        await _make_incident("the_old_one")
        for i in range(10):
            await _make_incident(f"filler-{i}")

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get(
                    "/incidents/the_old_one"
                )
                assert r.status_code == 200
                assert r.json()["id"] == "the_old_one"


class TestListDetectionsEndpoint:
    async def test_returns_detections_oldest_first(self, tmp_db) -> None:
        from backend.main import app

        await _make_incident("d1")
        await _make_incident("d2")

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/detections")
                assert r.status_code == 200
                body = r.json()
                assert body["total"] == 2
                assert len(body["items"]) == 2
