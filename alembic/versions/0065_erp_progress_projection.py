"""Track the last staff training percentage accepted by ERP.

Revision ID: 0065_erp_progress_projection
Revises: 0064_facilitator_nominations
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0065_erp_progress_projection"
down_revision = "0064_facilitator_nominations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "course_completions",
        sa.Column("erp_synced_pct", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("course_completions", "erp_synced_pct")
