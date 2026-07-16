"""add incident status

Revision ID: 3df6036b70bb
Revises: 819b7b1557ac
Created: 2026-07-16 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "3df6036b70bb"
down_revision: Union[str, None] = "819b7b1557ac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("status", sa.String(length=16), nullable=False, server_default="open")
        )
        batch_op.create_index(
            batch_op.f("ix_incidents_status"), ["status"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_incidents_status"))
        batch_op.drop_column("status")
