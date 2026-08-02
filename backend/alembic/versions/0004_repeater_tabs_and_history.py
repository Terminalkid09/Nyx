"""add repeater_tabs and repeater_history tables

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-25
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "repeater_tabs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "repeater_history",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("tab_id", sa.String(64), sa.ForeignKey("repeater_tabs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("headers", sa.JSON, nullable=True),
        sa.Column("body", sa.Text, nullable=True),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_headers", sa.JSON, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("time_ms", sa.Integer, nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("repeater_history")
    op.drop_table("repeater_tabs")
