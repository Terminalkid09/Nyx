"""add custom_scanner_checks and match_domain

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-23
"""
import uuid
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "target_scope_rules",
        sa.Column("match_domain", sa.Boolean, server_default=sa.text("false"), nullable=False),
    )

    op.create_table(
        "custom_scanner_checks",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(16), server_default="medium", nullable=False),
        sa.Column("match_type", sa.String(16), server_default="response_body", nullable=False),
        sa.Column("match_pattern", sa.String(1024), nullable=False),
        sa.Column("is_regex", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("payload", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("custom_scanner_checks")
    op.drop_column("target_scope_rules", "match_domain")
