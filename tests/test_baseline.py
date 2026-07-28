"""Behavioral baseline detection and its runtime toggle.

The design commitment under test: novelty, not badness. The detector never
judges a command line or a hash -- it only asks whether a host has shown this
exact (image, parent image) pair before, so the tests that matter most are
the boundary ones: a combination seen once must never fire twice, a host
still in its learning phase must stay silent even on a genuinely new
combination, and a mature host's baseline must survive a restart instead of
re-learning from scratch.

The runtime-settings half is tested separately: it is the one setting in this
project that changes without a restart, so its round trip through the
database -- write, then read back on a fresh instance -- is the case that
would silently break if the bridge between `config.py`'s frozen default and
the live in-memory value were wired wrong.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.engine.baseline import BASELINE_RULE_ID, BaselineDetector
from backend.engine.runtime_settings import RuntimeSettings
from backend.models import db
from backend.models.schemas import Event, Severity

BASE = datetime(2026, 7, 12, 10, 0, 0, tzinfo=timezone.utc)


def proc(
    host: str = "LAB-WIN11",
    image: str = r"C:\Windows\System32\cmd.exe",
    parent_image: str = r"C:\Windows\explorer.exe",
    offset_seconds: float = 0,
) -> Event:
    return Event(
        event_id=1,
        host=host,
        image=image,
        parent_image=parent_image,
        timestamp=BASE + timedelta(seconds=offset_seconds),
    )


class TestLearningPhase:
    async def test_new_combination_is_silent_while_still_learning(self, tmp_db) -> None:
        """A host under the learning threshold never alerts, even on a
        combination it has genuinely never shown before."""
        detector = BaselineDetector(learning_events=5)
        for i in range(5):
            result = await detector.observe(
                proc(image=rf"C:\tools\proc{i}.exe", offset_seconds=i)
            )
            assert result is None

    async def test_alerts_once_past_the_learning_threshold(self, tmp_db) -> None:
        detector = BaselineDetector(learning_events=3)
        for i in range(3):
            await detector.observe(proc(image=rf"C:\tools\proc{i}.exe", offset_seconds=i))

        result = await detector.observe(proc(image=r"C:\tools\proc_new.exe", offset_seconds=99))
        assert result is not None
        assert result.rule_id == BASELINE_RULE_ID
        assert result.severity is Severity.LOW

    async def test_learning_phase_is_scoped_per_host(self, tmp_db) -> None:
        """A brand-new host does not inherit another host's mature baseline
        and skip straight to alerting."""
        detector = BaselineDetector(learning_events=3)
        for i in range(3):
            await detector.observe(proc(host="WS-01", image=rf"C:\tools\p{i}.exe", offset_seconds=i))
        # WS-01 is now past learning; WS-02 has contributed nothing yet.
        result = await detector.observe(proc(host="WS-02", image=r"C:\tools\p0.exe", offset_seconds=50))
        assert result is None


class TestNoveltyDetection:
    async def test_same_combination_never_fires_twice(self, tmp_db) -> None:
        detector = BaselineDetector(learning_events=0)
        first = await detector.observe(proc(offset_seconds=0))
        second = await detector.observe(proc(offset_seconds=10))
        assert first is not None
        assert second is None

    async def test_different_parent_is_a_new_combination(self, tmp_db) -> None:
        """Same image, different parent -- a genuinely different combination,
        so it must be evaluated on its own, not treated as a repeat."""
        detector = BaselineDetector(learning_events=0)
        await detector.observe(proc(parent_image=r"C:\Windows\explorer.exe", offset_seconds=0))
        result = await detector.observe(proc(parent_image=r"C:\Windows\services.exe", offset_seconds=10))
        assert result is not None

    async def test_non_process_create_events_are_ignored(self, tmp_db) -> None:
        detector = BaselineDetector(learning_events=0)
        event = Event(event_id=3, host="LAB-WIN11", timestamp=BASE)  # network connect
        assert await detector.observe(event) is None

    async def test_evidence_reports_the_combination(self, tmp_db) -> None:
        detector = BaselineDetector(learning_events=0)
        result = await detector.observe(proc())
        assert result is not None
        assert result.evidence["host"] == "LAB-WIN11"
        assert result.evidence["image"] == r"C:\Windows\System32\cmd.exe"
        assert result.evidence["parent_image"] == r"C:\Windows\explorer.exe"
        assert result.evidence["host_known_combinations"] == 1


class TestPersistence:
    async def test_observations_are_written_through_to_the_database(self, tmp_db) -> None:
        detector = BaselineDetector(learning_events=0)
        await detector.observe(proc())
        rows = await db.list_baseline_observations()
        assert len(rows) == 1
        assert rows[0].host == "LAB-WIN11"

    async def test_a_mature_baseline_survives_a_restart(self, tmp_db) -> None:
        """The whole point of persisting to the database: a freshly
        constructed detector that loads existing history does not re-learn
        combinations it already knows, and does not reopen a learning phase
        for a host that already has one."""
        first = BaselineDetector(learning_events=2)
        await first.observe(proc(image=r"C:\tools\a.exe", offset_seconds=0))
        await first.observe(proc(image=r"C:\tools\b.exe", offset_seconds=1))

        second = BaselineDetector(learning_events=2)
        await second.load()

        # Already-known combination: still silent.
        assert await second.observe(proc(image=r"C:\tools\a.exe", offset_seconds=2)) is None
        # A genuinely new one: alerts immediately, no re-learning period,
        # because the host already had 2 known combinations before restart.
        result = await second.observe(proc(image=r"C:\tools\c.exe", offset_seconds=3))
        assert result is not None

    async def test_hosts_tracked_reflects_loaded_state(self, tmp_db) -> None:
        detector = BaselineDetector(learning_events=0)
        await detector.observe(proc(host="WS-01"))
        await detector.observe(proc(host="WS-02", image=r"C:\tools\other.exe"))

        reloaded = BaselineDetector(learning_events=0)
        await reloaded.load()
        assert reloaded.hosts_tracked == 2


class TestRuntimeSettings:
    async def test_default_before_load_matches_config(self) -> None:
        rs = RuntimeSettings()
        # Whatever config.py's static default is, the instance mirrors it
        # before load() ever touches the database.
        from backend.config import settings

        assert rs.behavior_baseline_enabled == settings.behavior_baseline_enabled

    async def test_load_falls_back_to_config_default_when_never_set(self, tmp_db) -> None:
        rs = RuntimeSettings()
        await rs.load()
        from backend.config import settings

        assert rs.behavior_baseline_enabled == settings.behavior_baseline_enabled

    async def test_set_persists_and_is_visible_to_a_fresh_instance(self, tmp_db) -> None:
        rs = RuntimeSettings()
        await rs.set_behavior_baseline_enabled(True)
        assert rs.behavior_baseline_enabled is True

        reloaded = RuntimeSettings()
        await reloaded.load()
        assert reloaded.behavior_baseline_enabled is True

    async def test_as_dict_reports_current_value(self) -> None:
        rs = RuntimeSettings()
        rs.behavior_baseline_enabled = True
        assert rs.as_dict() == {"behavior_baseline_enabled": True}


class TestSettingsEndpoint:
    async def test_get_and_put_admin_settings(self, tmp_db) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as c:
                initial = await c.get("/admin/settings")
                assert initial.status_code == 200
                assert "behavior_baseline_enabled" in initial.json()

                updated = await c.put(
                    "/admin/settings", json={"behavior_baseline_enabled": True}
                )
                assert updated.status_code == 200
                assert updated.json()["behavior_baseline_enabled"] is True

                confirm = await c.get("/admin/settings")
                assert confirm.json()["behavior_baseline_enabled"] is True
