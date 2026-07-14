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
    # An incident's lifecycle: new -> in_progress -> closed. Set by the analyst,
    # not the engine, so upsert must never overwrite it -- see upsert_incident.
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    # Analyst verdict, set at any point: tp, fp, tp_benign, inconclusive, or "".
    classification: Mapped[str] = mapped_column(String(16), default="")
    # Free-text analyst notes, persisted and shown in the report.
    notes: Mapped[str] = mapped_column(Text, default="")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


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

    missing = {"detections", "incidents"} - set(tables)
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
    status: str | None = None,
    exclude_status: str | None = None,
) -> list[IncidentRow]:
    """Most recent incidents, newest first (the console leads with the worst).

    `status` filters to one lifecycle state; `exclude_status` drops one (used to
    keep closed incidents out of the live queue). They are separate params
    because the queue wants "everything except closed" while the Closed tab wants
    "only closed" -- two different filters, not one.
    """
    async with Session() as session:
        stmt = select(IncidentRow).order_by(IncidentRow.last_seen.desc()).limit(limit)
        if actionable_only:
            stmt = stmt.where(IncidentRow.actionable == 1)
        if status is not None:
            stmt = stmt.where(IncidentRow.status == status)
        if exclude_status is not None:
            stmt = stmt.where(IncidentRow.status != exclude_status)
        result = await session.execute(stmt)
        return list(result.scalars().all())


async def update_incident_triage(
    incident_id: str,
    status: str | None = None,
    classification: str | None = None,
    notes: str | None = None,
) -> IncidentRow | None:
    """Update an incident's analyst-owned fields. Returns the row, or None if
    the incident does not exist.

    Only the fields passed are changed, so setting a note does not reset the
    status. These columns belong to the analyst and are never touched by the
    engine's upsert -- this is the only path that writes them.
    """
    async with Session() as session:
        row = await session.get(IncidentRow, incident_id)
        if row is None:
            return None
        if status is not None:
            row.status = status
        if classification is not None:
            row.classification = classification
        if notes is not None:
            row.notes = notes
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
