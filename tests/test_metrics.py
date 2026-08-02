"""backend/engine/metrics.py -- the hand-rolled Prometheus exposition layer.

Two layers get tested: the Counter/Histogram primitives in isolation (label
formatting, cumulative bucket semantics, HELP/TYPE lines), and the actual
`GET /metrics` endpoint end-to-end, confirming it reflects real traffic that
just passed through `/ingest` rather than only ever showing zeros.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from backend.engine.metrics import Counter, Histogram, render_prometheus_text
from backend.engine.pipeline import pipeline


class TestCounter:
    def test_starts_at_zero_and_increments(self) -> None:
        c = Counter("test_total", "A test counter.")
        c.inc()
        c.inc(amount=4)
        lines = c.render()
        assert "# HELP test_total A test counter." in lines
        assert "# TYPE test_total counter" in lines
        assert "test_total 5" in lines

    def test_labels_are_tracked_independently(self) -> None:
        c = Counter("outcome_total", "By outcome.")
        c.inc(outcome="accepted")
        c.inc(outcome="accepted")
        c.inc(outcome="malformed")
        lines = c.render()
        assert 'outcome_total{outcome="accepted"} 2' in lines
        assert 'outcome_total{outcome="malformed"} 1' in lines

    def test_label_values_are_escaped(self) -> None:
        c = Counter("weird_total", "Escaping check.")
        c.inc(path='has "quotes" and \\backslash')
        rendered = "\n".join(c.render())
        assert '\\"quotes\\"' in rendered
        assert "\\\\backslash" in rendered


class TestHistogram:
    def test_observe_increments_every_bucket_at_or_above_value(self) -> None:
        h = Histogram("dur_seconds", "Duration.", buckets=(0.1, 0.5, 1.0))
        h.observe(0.3)
        lines = h.render()
        assert 'dur_seconds_bucket{le="0.1"} 0' in lines
        assert 'dur_seconds_bucket{le="0.5"} 1' in lines
        assert 'dur_seconds_bucket{le="1.0"} 1' in lines
        assert 'dur_seconds_bucket{le="+Inf"} 1' in lines

    def test_sum_and_count_accumulate(self) -> None:
        h = Histogram("dur_seconds", "Duration.", buckets=(1.0,))
        h.observe(0.25)
        h.observe(0.75)
        lines = h.render()
        assert "dur_seconds_sum 1.0" in lines
        assert "dur_seconds_count 2" in lines

    def test_value_above_every_boundary_only_hits_inf(self) -> None:
        h = Histogram("dur_seconds", "Duration.", buckets=(0.1, 0.5))
        h.observe(99.0)
        lines = h.render()
        assert 'dur_seconds_bucket{le="0.1"} 0' in lines
        assert 'dur_seconds_bucket{le="0.5"} 0' in lines
        assert 'dur_seconds_bucket{le="+Inf"} 1' in lines


class TestRenderPrometheusText:
    def test_includes_uptime_gauge_and_extra_gauges(self) -> None:
        text = render_prometheus_text(extra_gauges={"hunter_rules_loaded": 42.0})
        assert "hunter_uptime_seconds" in text
        assert "hunter_rules_loaded 42.0" in text

    def test_ends_with_trailing_newline(self) -> None:
        assert render_prometheus_text().endswith("\n")


class TestMetricsEndpoint:
    async def test_returns_prometheus_text_after_traffic(self, tmp_db) -> None:
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                await c.post(
                    "/ingest",
                    json={
                        "EventID": 1,
                        "Computer": "LAB-WIN11",
                        "Image": r"C:\Windows\System32\notepad.exe",
                        "ProcessGuid": "{g-metrics-1}",
                    },
                )
                r = await c.get("/metrics")
                assert r.status_code == 200
                assert r.headers["content-type"].startswith("text/plain")
                body = r.text
                assert "hunter_ingest_requests_total" in body
                assert 'outcome="accepted"' in body
                assert "hunter_http_requests_total" in body
                assert "hunter_rules_loaded" in body

    async def test_not_behind_the_api_key_gate(self, tmp_db, monkeypatch) -> None:
        """/metrics is a bare monitoring endpoint, same precedent as /health --
        a scraper on an internal network should not need HUNTER_API_KEY."""
        from backend.config import settings

        monkeypatch.setattr(settings, "api_key", "s3cret")
        pipeline.reset()
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                r = await c.get("/metrics")
                assert r.status_code == 200
