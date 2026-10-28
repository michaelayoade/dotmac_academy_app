"""Pin each entrance sitting to an immutable bank version at start.

Adds applicants.assessment_bank_version_id (tenant-consistent composite
FK to Learning question_bank_versions). Existing rows stay NULL: sittings
started before versioning cannot be truthfully re-pinned and are served
best-effort from the bank's current published version.

Revision ID: a009_applicant_bank_version_pin
Revises: a008_lab_console_activity
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a009_applicant_bank_version_pin"
down_revision = "a008_lab_console_activity"
branch_labels = None
depends_on = "lr_0010_question_bank_versions"


def upgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT current_user")) != "app_admin":
        raise ValueError("Academy assembly migration requires app_admin")
    if op.get_bind().scalar(sa.text("""
        SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
          WHERE attrelid=pg_catalog.to_regclass('public.applicants')
            AND attname='assessment_bank_version_id' AND NOT attisdropped)
          OR pg_catalog.to_regclass('public.ix_applicants_assessment_bank_version_id') IS NOT NULL
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
             WHERE conrelid=pg_catalog.to_regclass('public.applicants')
               AND conname='fk_applicants_tenant_assessment_bank_version')
    """)):
        raise ValueError("applicant bank version objects already exist")
    op.add_column(
        "applicants",
        sa.Column("assessment_bank_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="public",
    )
    op.create_foreign_key(
        "fk_applicants_tenant_assessment_bank_version",
        "applicants",
        "question_bank_versions",
        ["tenant_id", "assessment_bank_version_id"],
        ["tenant_id", "id"],
        source_schema="public",
        referent_schema="mod_learning",  # installed lr_0010._SCHEMA
    )
    op.create_index(
        "ix_applicants_assessment_bank_version_id", "applicants", ["assessment_bank_version_id"], schema="public"
    )



def downgrade() -> None:
    raise RuntimeError("Academy assembly reversal requires a reviewed new-facts disposition")
