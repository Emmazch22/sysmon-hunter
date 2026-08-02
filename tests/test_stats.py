"""backend/engine/stats.py and GET /stats -- the dashboard's aggregation.

Two layers: `build_stats()` directly against a seeded database (exact counts,
zero-filled day series, top-N ordering, the technique-name lookup falling
back to the bare ID for an unknown technique), and the HTTP endpoint (day
range validation, API-key gating consistent with every other JSON router,
and that `/dashboard` itself is an ungated page like `/incident/{id}`).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from httpx import ASGITransport, AsyncClient

from backend.engine.stats import build_stats
from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity

UTC = timezone.utc


async def _make_incident(
    incident_id: str,
    *,
    host: str = "WS-01",
    score: int = 8,
    status: str = "open",
    actionable: bool = True,
    first_seen: datetime | None = None,
    detections: list[tuple[str, str, list[str]]] | None = None,
) -> None:
    """Seed one incident with a controlled score (-> severity band), status,
    first_seen date, and an explicit list of (rule_id, title, attack) member
    detections -- independent of Incident.add()'s score bookkeeping, since
    these tests need to pin severity bands and dates precisely."""
    first_seen = first_seen or datetime.now(UTC)
    inc = Incident(
        id=incident_id, host=host, root_guid=f"g-{incident_id}",
        first_seen=first_seen, last_seen=first_seen,
    )
    inc.score = score
    await db.upsert_incident(inc, actionable=actionable)
    if status != "open":
        await db.update_incident_status(incident_id, status)

    for rule_id, title, attack in detections or [("SYS-001", "Test rule", ["T1566.001"])]:
        det = Detection(
            rule_id=rule_id, title=title, severity=Severity.HIGH, attack=attack,
            event=Event(event_id=1, timestamp=first_seen), matched_at=first_seen,
            incident_id=incident_id,
        )
        await db.save_detection(det)


class TestBuildStatsEmpty:
    async def test_empty_database_returns_zeroed_payload(self, tmp_db) -> None:
        data = await build_stats(days=7)
        assert data["totals"] == {
            "incidents": 0, "detections": 0, "open": 0,
            "actionable_open": 0, "closed": 0, "false_positive": 0,
        }
        assert len(data["incidents_per_day"]) == 7
        assert all(d["count"] == 0 for d in data["incidents_per_day"])
        assert data["top_rules"] == []
        assert data["top_techniques"] == []


class TestBuildStatsAggregation:
    async def test_totals_reflect_seeded_incidents(self, tmp_db) -> None:
        today = datetime.now(UTC)
        await _make_incident("i1", score=14, status="open", actionable=True, first_seen=today)
        await _make_incident("i2", score=8, status="closed", actionable=False, first_seen=today)
        await _make_incident(
            "i3", score=5, status="false_positive", actionable=False, first_seen=today
        )

        data = await build_stats(days=7)
        assert data["totals"]["incidents"] == 3
        assert data["totals"]["open"] == 1
        assert data["totals"]["actionable_open"] == 1
        assert data["totals"]["closed"] == 1
        assert data["totals"]["false_positive"] == 1
        assert data["totals"]["detections"] == 3

    async def test_severity_distribution_buckets_by_score(self, tmp_db) -> None:
        today = datetime.now(UTC)
        await _make_incident("crit", score=14, first_seen=today)
        await _make_incident("high", score=8, first_seen=today)
        await _make_incident("med", score=5, first_seen=today)

        data = await build_stats(days=7)
        by_sev = {row["severity"]: row["count"] for row in data["severity_distribution"]}
        assert by_sev["critical"] == 1
        assert by_sev["high"] == 1
        assert by_sev["medium"] == 1
        assert by_sev["low"] == 0
        assert by_sev["info"] == 0

    async def test_incidents_per_day_is_zero_filled_and_bucketed(self, tmp_db) -> None:
        today = datetime.now(UTC)
        yesterday = today - timedelta(days=1)
        await _make_incident("today-1", first_seen=today)
        await _make_incident("today-2", first_seen=today)
        await _make_incident("yesterday-1", first_seen=yesterday)

        data = await build_stats(days=7)
        by_date = {row["date"]: row["count"] for row in data["incidents_per_day"]}
        assert by_date[today.date().isoformat()] == 2
        assert by_date[yesterday.date().isoformat()] == 1
        # Every other day in the 7-day window is present and zero, not omitted.
        assert len(by_date) == 7

    async def test_days_parameter_bounds_the_series_length(self, tmp_db) -> None:
        data = await build_stats(days=30)
        assert len(data["incidents_per_day"]) == 30

    async def test_days_parameter_is_clamped_to_max(self, tmp_db) -> None:
        from backend.engine.stats import MAX_DAYS

        data = await build_stats(days=9999)
        assert data["range_days"] == MAX_DAYS
        assert len(data["incidents_per_day"]) == MAX_DAYS

    async def test_top_rules_ranked_by_detection_count(self, tmp_db) -> None:
        await _make_incident(
            "i1",
            detections=[
                ("SYS-006", "Staging path", ["T1105"]),
                ("SYS-006", "Staging path", ["T1105"]),
                ("SYS-009", "Download cradle", ["T1059.001"]),
            ],
        )
        data = await build_stats(days=7)
        assert data["top_rules"][0] == {"rule_id": "SYS-006", "title": "Staging path", "count": 2}
        assert data["top_rules"][1] == {
            "rule_id": "SYS-009", "title": "Download cradle", "count": 1
        }

    async def test_top_techniques_counts_across_all_detections(self, tmp_db) -> None:
        await _make_incident(
            "i1",
            detections=[
                ("SYS-001", "x", ["T1566.001", "T1204"]),
                ("SYS-002", "y", ["T1566.001"]),
            ],
        )
        data = await build_stats(days=7)
        by_id = {row["technique_id"]: row["count"] for row in data["top_techniques"]}
        assert by_id["T1566.001"] == 2
        assert by_id["T1204"] == 1

    async def test_unknown_technique_falls_back_to_bare_id_as_name(self, tmp_db) -> None:
        await _make_incident("i1", detections=[("SYS-999", "x", ["T9999.999"])])
        data = await build_stats(days=7)
        row = next(r for r in data["top_techniques"] if r["technique_id"] == "T9999.999")
        assert row["name"] == "T9999.999"

    async def test_top_rules_capped_at_ten(self, tmp_db) -> None:
        dets = [(f"SYS-{i:03d}", f"rule {i}", ["T1105"]) for i in range(15)]
        await _make_incident("i1", detections=dets)
        data = await build_stats(days=7)
        assert len(data["top_rules"]) == 10


class TestStatsEndpoint:
    async def test_returns_200_with_default_range(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/stats")
                assert r.status_code == 200
                assert r.json()["range_days"] == 14

    async def test_days_query_param_is_honored(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/stats?days=30")
                assert r.status_code == 200
                assert r.json()["range_days"] == 30

    async def test_out_of_range_days_is_rejected(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                assert (await c.get("/stats?days=0")).status_code == 422
                assert (await c.get("/stats?days=91")).status_code == 422

    async def test_gated_by_api_key_when_configured(self, tmp_db, monkeypatch) -> None:
        from backend.config import settings

        monkeypatch.setattr(settings, "api_key", "s3cret")
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                assert (await c.get("/stats")).status_code == 401
                assert (await c.get("/stats", headers={"X-API-Key": "s3cret"})).status_code == 200


class TestDashboardPage:
    async def test_dashboard_page_serves_html(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/dashboard")
                assert r.status_code == 200
                assert "text/html" in r.headers["content-type"]

    async def test_dashboard_page_stays_open_with_api_key_configured(
        self, tmp_db, monkeypatch
    ) -> None:
        """Same precedent as /, /health, and /incident/{id}: page routes are
        never wrapped with the API-key dependency, only the JSON routers are."""
        from backend.config import settings

        monkeypatch.setattr(settings, "api_key", "s3cret")
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                assert (await c.get("/dashboard")).status_code == 200
