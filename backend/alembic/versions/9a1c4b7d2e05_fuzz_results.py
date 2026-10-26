"""fuzz_results

BUG-04 fase B: fuzzer results move out of the ``fuzz_jobs.results`` JSON blob
into one row per payload, with bodies already truncated by the service.

Revision ID: 9a1c4b7d2e05
Revises: c4f2e6989355
Create Date: 2026-10-24 18:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a1c4b7d2e05'
down_revision: Union[str, None] = 'c4f2e6989355'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'fuzz_results',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('job_id', sa.Uuid(), nullable=False),
        sa.Column('seq', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('status', sa.Integer(), nullable=True),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('time_ms', sa.Integer(), nullable=False),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('waf_detected', sa.String(length=64), nullable=True),
        sa.Column('grep_results', sa.JSON(), nullable=False),
        sa.Column('extracted', sa.JSON(), nullable=False),
        sa.Column('request', sa.Text(), nullable=True),
        sa.Column('response', sa.Text(), nullable=True),
        sa.Column('truncated', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['fuzz_jobs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_fuzz_results_job_seq', 'fuzz_results', ['job_id', 'seq'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_fuzz_results_job_seq', table_name='fuzz_results')
    op.drop_table('fuzz_results')
