"""add incident notes

Revision ID: 819b7b1557ac
Revises: fd21a0af14af
Created: 2026-07-13 20:14:15.871714
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "819b7b1557ac"
down_revision: Union[str, None] = "fd21a0af14af"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("notes", sa.Text(), nullable=False, server_default="")
        )


def downgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_column("notes")
