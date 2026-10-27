"""finding triage status and severity override

A finding could not be dismissed, retested or re-rated: the only options were
reporting it again or deleting it, and deleting loses the evidence. Two columns
carry the workflow instead. ``triage_status`` has a server default so existing
rows stay valid, and both columns are nullable-safe for databases created by
``Base.metadata.create_all``.

Revision ID: a3f1c9d7b2e4
Revises: b7e3d1f4a6c2
Create Date: 2026-10-27 12:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f1c9d7b2e4'
down_revision: Union[str, None] = 'b7e3d1f4a6c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if 'findings' not in inspector.get_table_names():
        return set()
    return {column['name'] for column in inspector.get_columns('findings')}


def upgrade() -> None:
    columns = _columns()
    if 'triage_status' not in columns:
        op.add_column(
            'findings',
            sa.Column(
                'triage_status',
                sa.String(length=16),
                nullable=False,
                server_default='open',
            ),
        )
    if 'severity_override' not in columns:
        op.add_column(
            'findings',
            sa.Column('severity_override', sa.String(length=16), nullable=True),
        )


def downgrade() -> None:
    columns = _columns()
    if 'severity_override' in columns:
        op.drop_column('findings', 'severity_override')
    if 'triage_status' in columns:
        op.drop_column('findings', 'triage_status')
