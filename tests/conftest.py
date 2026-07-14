"""Shared test fixtures.

Every test runs against an isolated in-memory database and a freshly built
pipeline, so no test can see another test's detections. Correlation state is
global by design in production -- one collector, one tree -- which makes leaking
it between tests very easy and very confusing, hence the hard reset here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from backend.engine.correlator import IncidentEngine, ProcessTree
from backend.models.schemas import Event, Rule, Severity


@pytest.fixture
def tree() -> ProcessTree:
    """A process tree with a generous TTL, so nothing expires mid-test."""
    return ProcessTree(ttl=timedelta(hours=1))


@pytest.fixture
def incidents(tree: ProcessTree) -> IncidentEngine:
    """An incident engine with the production defaults."""
    return IncidentEngine(tree=tree, window=timedelta(minutes=10), score_threshold=12)


@pytest.fixture
def at() -> Any:
    """Build deterministic timestamps: at(0), at(30) -> 30 seconds later.

    Correlation is time-sensitive, so tests must control the clock rather than
    hoping wall-clock time cooperates.
    """
    base = datetime(2026, 7, 12, 10, 0, 0, tzinfo=timezone.utc)

    def _at(offset_seconds: int = 0) -> datetime:
        return base + timedelta(seconds=offset_seconds)

    return _at


def make_event(
    event_id: int = 1,
    host: str = "LAB-WIN11",
    image: str | None = None,
    parent_image: str | None = None,
    command_line: str | None = None,
    guid: str | None = None,
    parent_guid: str | None = None,
    timestamp: datetime | None = None,
    **raw: Any,
) -> Event:
    """Build an Event without going through the normalizer."""
    return Event(
        event_id=event_id,
        host=host,
        image=image,
        parent_image=parent_image,
        command_line=command_line,
        process_guid=guid,
        parent_process_guid=parent_guid,
        timestamp=timestamp or datetime.now(timezone.utc),
        raw=raw,
    )


def make_rule(
    rule_id: str = "TEST-001",
    event_id: int = 1,
    severity: Severity = Severity.MEDIUM,
    condition: str = "all",
    attack: list[str] | None = None,
    **detection: Any,
) -> Rule:
    """Build a Rule from keyword args, so tests read like the YAML they mirror."""
    return Rule(
        id=rule_id,
        title=f"Test rule {rule_id}",
        event_id=event_id,
        severity=severity,
        attack=attack or [],
        detection=detection,
        condition=condition,
    )


import pytest_asyncio


@pytest_asyncio.fixture
async def tmp_db(tmp_path, monkeypatch):
    """An isolated on-disk database per test, with the schema created."""
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from backend.models import db as dbmod

    url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(dbmod.Base.metadata.create_all)
    monkeypatch.setattr(dbmod, "engine", engine)
    monkeypatch.setattr(
        dbmod,
        "Session",
        async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False),
    )
    yield
    await engine.dispose()
