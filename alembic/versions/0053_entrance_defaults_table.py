"""Move the academy entrance defaults off `tenants` into their own table.

`tenants.default_entrance_bank_id` and `default_entrance_time_limit_minutes`
are a product concern on a platform table. Carrying them there is what made this
repo's tenancy model un-swappable for the kernel's, so they move to a table this
repo owns.

Expand/contract in one revision is safe here and would not be at scale: this is
a single-tenant deployment with one row in `tenants`, the columns are nullable
with no FK pointing at them, and the copy is a single INSERT..SELECT inside the
migration's transaction. If that ever stops being true, split it — create and
backfill, deploy the readers, then drop in a later revision.

The downgrade restores the columns and copies the values back, so the pair is
reversible without data loss.

Revision ID: 0053_entrance_defaults
Revises: 0052_erp_applicant_assessments
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0053_entrance_defaults"
down_revision = "0052_erp_applicant_assessments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_entrance_defaults",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("default_bank_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("default_time_limit_minutes", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # Only rows that actually carry a default. A tenant with neither value set
    # has no configuration to preserve, and an empty row would assert one.
    op.execute(
        """
        INSERT INTO tenant_entrance_defaults
            (tenant_id, default_bank_id, default_time_limit_minutes)
        SELECT id, default_entrance_bank_id, default_entrance_time_limit_minutes
        FROM tenants
        WHERE default_entrance_bank_id IS NOT NULL
           OR default_entrance_time_limit_minutes IS NOT NULL
        """
    )

    op.drop_column("tenants", "default_entrance_bank_id")
    op.drop_column("tenants", "default_entrance_time_limit_minutes")


def downgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("default_entrance_bank_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column("default_entrance_time_limit_minutes", sa.Integer(), nullable=True),
    )
    op.execute(
        """
        UPDATE tenants t
        SET default_entrance_bank_id = d.default_bank_id,
            default_entrance_time_limit_minutes = d.default_time_limit_minutes
        FROM tenant_entrance_defaults d
        WHERE d.tenant_id = t.id
        """
    )
    op.drop_table("tenant_entrance_defaults")
