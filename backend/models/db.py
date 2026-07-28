"""Persistence layer.

Detections and incidents survive a restart; the process tree does not. That is
deliberate. The tree is a live working set whose value decays in minutes, while
detections are evidence and incidents are findings -- both need to still be
there tomorrow morning.

SQLite via aiosqlite is enough for a single collector. The repository functions
below are the only place SQL is written, so swapping in Postgres later means
changing the URL in config and nothing else.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    delete,
    inspect,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from backend.config import settings
from backend.models.schemas import Detection, Incident

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Declarative base for all tables."""


class DetectionRow(Base):
    """A rule firing, flattened for storage.

    The originating event is kept whole in `raw_event` rather than being spread
    across columns. When a rule turns out to be a false positive six weeks from
    now, the analyst needs the event exactly as it arrived, not our lossy
    projection of it.
    """

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    attack: Mapped[list[str]] = mapped_column(JSON, default=list)

    host: Mapped[str] = mapped_column(String(128), index=True)
    image: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parent_image: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process_guid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    incident_id: Mapped[Optional[str]] = mapped_column(
        String(32), ForeignKey("incidents.id"), nullable=True, index=True
    )

    # Supporting numbers for statistical detections (beacon interval, jitter,
    # regularity). Empty for rule-based detections.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class IncidentRow(Base):
    """A correlated group of detections.

    Member detections are not duplicated here; they point back via
    `detections.incident_id`. Only the aggregates the console needs for its list
    view are denormalized, so rendering the incident list is a single query.
    """

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(Text, default="")
    host: Mapped[str] = mapped_column(String(128), index=True)
    root_guid: Mapped[str] = mapped_column(String(64))
    root_image: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)

    chain: Mapped[list[str]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Flat list of process-tree nodes spanning the incident (see correlator
    # subtree). Stored so the full branching tree survives a restart, since the
    # in-memory ProcessTree is pruned.
    process_tree: Mapped[list[dict]] = mapped_column(JSON, default=list)
    actionable: Mapped[int] = mapped_column(Integer, default=0)  # SQLite has no bool

    # --- SOC triage state ---
    # An incident's lifecycle: open -> closed, or open -> false_positive. Set by
    # the analyst, not the engine, so upsert must never overwrite it -- see
    # upsert_incident. One of IncidentStatus's values, stored as plain text
    # rather than a DB-level enum so a future status needs no migration to add.
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    # Free-text analyst notes, persisted and shown in the report.
    notes: Mapped[str] = mapped_column(Text, default="")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SettingRow(Base):
    """A runtime-editable setting, keyed by name.

    Everything in `config.py` is read once at startup and frozen for the
    life of the process. This table exists for the handful of settings that
    need to change without a restart -- the behavior-baseline toggle is the
    first, reached from the console's settings dropdown. Deliberately generic
    (one key, one value) so the next such setting is a new row, not a new
    migration.
    """

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))


class BaselineObservationRow(Base):
    """One (host, image, parent_image) combination the baseline detector has
    ever seen.

    This is long-term memory, not a session cache: it is what lets the
    detector recognise "we've seen this before" across restarts, and it is
    deliberately untouched by `reset_database` -- an analyst clearing out
    detections and incidents is not asking to forget a host's learned
    behavior too.
    """

    __tablename__ = "baseline_observations"

    host: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)
    image: Mapped[str] = mapped_column(Text, primary_key=True)
    parent_image: Mapped[str] = mapped_column(Text, primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    seen_count: Mapped[int] = mapped_column(Integer, default=1)


engine = create_async_engine(settings.db_url, echo=False)
Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Verify the database has been migrated. Does not create tables.

    Schema ownership belongs to Alembic and nowhere else. An earlier version
    called `create_all()` here, which quietly created any *missing* table but
    could not alter an *existing* one -- so adding a column to a model produced
    a server that started cleanly and then failed at the first query with
    "no such column". The failure surfaced far from its cause.

    Now startup fails immediately, with an instruction, if migrations are behind.
    """
    async with engine.begin() as conn:
        tables = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_table_names()
        )

    missing = {"detections", "incidents", "settings", "baseline_observations"} - set(tables)
    if missing:
        raise RuntimeError(
            f"Database is not migrated (missing tables: {', '.join(sorted(missing))}).\n"
            f"Run:  python -m alembic upgrade head"
        )

    log.info("Database ready at %s", settings.db_url)


async def save_detection(detection: Detection) -> None:
    """Persist a single detection."""
    event = detection.event
    row = DetectionRow(
        rule_id=detection.rule_id,
        title=detection.title,
        severity=detection.severity.value,
        attack=detection.attack,
        host=event.host,
        image=event.image,
        parent_image=event.parent_image,
        command_line=event.command_line,
        process_guid=event.process_guid,
        incident_id=detection.incident_id,
        evidence=detection.evidence,
        matched_at=detection.matched_at,
        raw_event=event.raw,
    )
    async with Session() as session:
        session.add(row)
        await session.commit()


async def upsert_incident(incident: Incident, actionable: bool) -> None:
    """Insert or update an incident.

    Incidents are mutable while open -- every new detection changes the score,
    the severity band and the technique list -- so this runs on each correlation
    rather than once at close time. If the process crashes mid-incident, what is
    on disk is still accurate as of the last detection seen.
    """
    async with Session() as session:
        row = await session.get(IncidentRow, incident.id)
        if row is None:
            row = IncidentRow(id=incident.id, first_seen=incident.first_seen)
            session.add(row)

        row.title = incident.title
        row.host = incident.host
        row.root_guid = incident.root_guid
        row.root_image = incident.root_image
        row.severity = incident.severity.value
        row.score = incident.score
        row.detection_count = len(incident.detections)
        row.chain = incident.chain
        row.process_tree = incident.process_tree
        row.techniques = incident.techniques
        row.actionable = int(actionable)
        row.last_seen = incident.last_seen

        await session.commit()


async def list_detections(limit: int = 100) -> list[DetectionRow]:
    """Most recent detections, newest last (the console appends downward)."""
    async with Session() as session:
        result = await session.execute(
            select(DetectionRow).order_by(DetectionRow.matched_at.desc()).limit(limit)
        )
        return list(reversed(result.scalars().all()))


async def list_incidents(
    limit: int = 50,
    actionable_only: bool = False,
) -> list[IncidentRow]:
    """Most recent incidents, newest first (the console leads with the worst)."""
    async with Session() as session:
        stmt = select(IncidentRow).order_by(IncidentRow.last_seen.desc()).limit(limit)
        if actionable_only:
            stmt = stmt.where(IncidentRow.actionable == 1)
        result = await session.execute(stmt)
        return list(result.scalars().all())


async def update_incident_notes(incident_id: str, notes: str) -> "IncidentRow | None":
    """Set (or clear) an incident's analyst note. The note belongs to the
    analyst and is never touched by the engine's upsert."""
    async with Session() as session:
        row = await session.get(IncidentRow, incident_id)
        if row is None:
            return None
        row.notes = notes
        await session.commit()
        await session.refresh(row)
        return row


async def update_incident_status(incident_id: str, status: str) -> "IncidentRow | None":
    """Set an incident's triage status. Never called by the engine's upsert --
    only by the analyst, from the console or the incident page."""
    async with Session() as session:
        row = await session.get(IncidentRow, incident_id)
        if row is None:
            return None
        row.status = status
        await session.commit()
        await session.refresh(row)
        return row


async def get_incident_detections(incident_id: str) -> list[DetectionRow]:
    """Every detection belonging to one incident, in the order they fired."""
    async with Session() as session:
        result = await session.execute(
            select(DetectionRow)
            .where(DetectionRow.incident_id == incident_id)
            .order_by(DetectionRow.matched_at.asc())
        )
        return list(result.scalars().all())


async def count_detections() -> int:
    """Total detections on record, used by the console's stat strip."""
    async with Session() as session:
        result = await session.execute(select(DetectionRow.id))
        return len(result.scalars().all())


async def reset_database() -> None:
    """Delete every detection and incident.

    This clears the tables rather than deleting `data/hunter.db` off disk.
    The file sits behind an open connection pool and its schema is owned by
    Alembic (see `init_db`), so unlinking it while the server is running would
    leave the engine pointed at a file with no tables until someone runs the
    migration by hand -- a live 500 dressed up as a "reset". Truncating both
    tables in one transaction reaches the same end an analyst wants -- an
    empty console -- without either problem, and needs no restart.
    """
    async with Session() as session:
        await session.execute(delete(DetectionRow))
        await session.execute(delete(IncidentRow))
        await session.commit()
    log.warning("Database reset: all detections and incidents deleted")


async def get_setting(key: str, default: str) -> str:
    """Read a runtime setting, falling back to `default` if it was never set."""
    async with Session() as session:
        row = await session.get(SettingRow, key)
        return row.value if row is not None else default


async def set_setting(key: str, value: str) -> None:
    """Write a runtime setting, creating it on first use."""
    async with Session() as session:
        row = await session.get(SettingRow, key)
        if row is None:
            row = SettingRow(key=key, value=value)
            session.add(row)
        else:
            row.value = value
        await session.commit()


async def list_baseline_observations() -> list[BaselineObservationRow]:
    """Every (host, image, parent_image) combination on record.

    Loaded once, in full, at startup -- the detector keeps its own in-memory
    copy for the life of the process rather than round-tripping to the
    database on every event. Fine at the scale this tool targets; see
    `BaselineDetector` for why that trade-off is safe here.
    """
    async with Session() as session:
        result = await session.execute(select(BaselineObservationRow))
        return list(result.scalars().all())


async def record_baseline_observation(
    host: str, image: str, parent_image: str, first_seen: datetime
) -> None:
    """Persist a newly-learned (host, image, parent_image) combination.

    Only called once per combination -- the detector's in-memory set is what
    prevents this from running on every matching event afterward, so write
    volume stays bounded by how many distinct combinations exist, not by
    event volume.
    """
    async with Session() as session:
        row = BaselineObservationRow(
            host=host, image=image, parent_image=parent_image, first_seen=first_seen
        )
        await session.merge(row)
        await session.commit()
