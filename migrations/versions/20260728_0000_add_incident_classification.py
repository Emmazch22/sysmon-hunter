"""add incident classification

Revision ID: 5a9e2c1f4b3d
Revises: 3df6036b70bb
Created: 2026-07-28 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "5a9e2c1f4b3d"
down_revision: Union[str, None] = "3df6036b70bb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("classification", sa.String(length=64), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_incidents_classification"), ["classification"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_incidents_classification"))
        batch_op.drop_column("classification")
