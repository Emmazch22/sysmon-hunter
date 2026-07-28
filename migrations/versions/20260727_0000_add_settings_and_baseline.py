"""add settings and baseline_observations

Revision ID: 5a3f7c9e1b2d
Revises: 3df6036b70bb
Created: 2026-07-27 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "5a3f7c9e1b2d"
down_revision: Union[str, None] = "3df6036b70bb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # A tiny key/value store for settings that need to change without a
    # restart -- the first is the behavior-baseline toggle, but the shape is
    # generic on purpose so the next runtime-editable setting needs no new
    # migration, just a new key.
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", sa.String(length=256), nullable=False),
    )

    # Long-term memory for the behavioral-baseline detector: every distinct
    # (host, image, parent_image) combination ever observed. Deliberately not
    # touched by /admin/database's reset -- months of learned baseline are not
    # the same kind of data as detections and incidents, and wiping one should
    # not silently wipe the other.
    op.create_table(
        "baseline_observations",
        sa.Column("host", sa.String(length=128), primary_key=True),
        sa.Column("image", sa.Text(), primary_key=True),
        sa.Column("parent_image", sa.Text(), primary_key=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("seen_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        op.f("ix_baseline_observations_host"),
        "baseline_observations",
        ["host"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_baseline_observations_host"), table_name="baseline_observations"
    )
    op.drop_table("baseline_observations")
    op.drop_table("settings")
