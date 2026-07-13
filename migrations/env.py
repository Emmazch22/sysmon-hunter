"""Alembic environment.

Two things here are not the Alembic default, and both matter:

1. The database URL comes from `backend.config.settings`, not from alembic.ini.
   One source of truth means a migration cannot be run against a different
   database than the application uses -- which is exactly the kind of mistake
   that is invisible until production data is missing.

2. The engine is async, because the application's is. Alembic's migration code
   is synchronous, so the async connection is bridged with `run_sync`.

Autogenerate compares `Base.metadata` against the live database, so every model
in backend/models/db.py must be imported before `target_metadata` is read.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from backend.config import settings

# Importing the models registers every table on Base.metadata. Without this,
# autogenerate sees an empty schema and cheerfully writes a migration that drops
# all your tables.
from backend.models.db import Base  # noqa: F401

config = context.config

# Inject the application's URL, overriding whatever alembic.ini might hold.
config.set_main_option("sqlalchemy.url", settings.db_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting.

    Useful for reviewing what a migration will do before it touches anything,
    and for handing SQL to a DBA who will not run Python against production.
    """
    context.configure(
        url=settings.db_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite cannot ALTER a column in place. Batch mode rebuilds the table
        # behind the scenes -- create new, copy rows, drop old, rename -- which
        # is what makes an ALTER on SQLite possible at all.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run the migrations on an already-open synchronous connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        # Detect column type changes, not just added and dropped columns.
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Open an async engine and run the migrations through it."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point when Alembic runs against a live database."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
