"""Pin each entrance sitting to an immutable bank version at start.

Adds applicants.assessment_bank_version_id (tenant-consistent composite
FK to Learning question_bank_versions). Existing rows stay NULL: sittings
started before versioning cannot be truthfully re-pinned and are served
best-effort from the bank's current published version.

Revision ID: 0065_applicant_bank_version_pin
Revises: 0064_facilitator_nominations
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0065_applicant_bank_version_pin"
down_revision = "0064_facilitator_nominations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "applicants",
        sa.Column("assessment_bank_version_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_applicants_tenant_assessment_bank_version",
        "applicants",
        "question_bank_versions",
        ["tenant_id", "assessment_bank_version_id"],
        ["tenant_id", "id"],
    )
    op.create_index(
        "ix_applicants_assessment_bank_version_id", "applicants", ["assessment_bank_version_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_applicants_assessment_bank_version_id", table_name="applicants")
    op.drop_constraint(
        "fk_applicants_tenant_assessment_bank_version", "applicants", type_="foreignkey"
    )
    op.drop_column("applicants", "assessment_bank_version_id")
