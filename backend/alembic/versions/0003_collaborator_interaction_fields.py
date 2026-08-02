"""add collaborator interaction detail fields

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-25
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("collaborator_interactions", sa.Column("method", sa.String(16), nullable=True))
    op.add_column("collaborator_interactions", sa.Column("url", sa.Text, nullable=True))
    op.add_column("collaborator_interactions", sa.Column("request_headers", sa.JSON, nullable=True))
    op.add_column("collaborator_interactions", sa.Column("body", sa.Text, nullable=True))
    op.add_column("collaborator_interactions", sa.Column("user_agent", sa.String(512), nullable=True))
    op.add_column("collaborator_interactions", sa.Column("query_type", sa.String(16), nullable=True))
    op.add_column("collaborator_interactions", sa.Column("query_name", sa.String(512), nullable=True))


def downgrade() -> None:
    op.drop_column("collaborator_interactions", "query_name")
    op.drop_column("collaborator_interactions", "query_type")
    op.drop_column("collaborator_interactions", "user_agent")
    op.drop_column("collaborator_interactions", "body")
    op.drop_column("collaborator_interactions", "request_headers")
    op.drop_column("collaborator_interactions", "url")
    op.drop_column("collaborator_interactions", "method")
