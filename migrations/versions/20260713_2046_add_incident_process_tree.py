"""add incident process_tree

Revision ID: fd21a0af14af
Revises: 78c81fa35be2
Created: 2026-07-13 20:46:25.451141
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "fd21a0af14af"
down_revision: Union[str, None] = "78c81fa35be2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("process_tree", sa.JSON(), nullable=True, server_default="[]")
        )


def downgrade() -> None:
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_column("process_tree")
