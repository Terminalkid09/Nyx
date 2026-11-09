"""authorization_profiles

F-01 introduced signed Rules-of-Engagement profiles, but the table was only
ever created by ``Base.metadata.create_all``. A database built strictly from
Alembic therefore had no ``authorization_profiles`` table and every RoE lookup
failed. The migration is idempotent because older development databases may
already contain the table from the create_all fallback.

Revision ID: b7e3d1f4a6c2
Revises: 9a1c4b7d2e05
Create Date: 2026-10-26 10:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7e3d1f4a6c2'
down_revision: Union[str, None] = '9a1c4b7d2e05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists() -> bool:
    return 'authorization_profiles' in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if _table_exists():
        return
    op.create_table(
        'authorization_profiles',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('targets', sa.JSON(), nullable=False),
        sa.Column('exclusions', sa.JSON(), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('max_rps', sa.Float(), nullable=False),
        sa.Column('signature', sa.String(length=128), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    if _table_exists():
        op.drop_table('authorization_profiles')
