"""Add scoped facilitator nominations without overloading learner enrollment.

Revision ID: 0064_facilitator_nominations
Revises: 0063_lab_console_activity
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0064_facilitator_nominations"
down_revision = "0063_lab_console_activity"
branch_labels = None
depends_on = None

NOMINATIONS = "facilitator_nominations"
REQUIREMENTS = "facilitator_requirements"


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def _tenant_table(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {table}_tenant_isolation ON {table} "
        f"USING (tenant_id = app_current_tenant_id()) "
        f"WITH CHECK (tenant_id = app_current_tenant_id());"
    )
    op.execute(f"REVOKE ALL PRIVILEGES ON {table} FROM PUBLIC;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_user, platform_api;")


def upgrade() -> None:
    op.create_table(
        NOMINATIONS,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("nominated_by_person_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("cohort_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("offering_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activation_reason", sa.String(40), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_facilitator_nominations_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_person",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "nominated_by_person_id"],
            ["people.tenant_id", "people.id"],
            name="fk_facilitator_nominations_nominator",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "cohort_id"],
            ["cohorts.tenant_id", "cohorts.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_cohort",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "offering_id"],
            ["course_offerings.tenant_id", "course_offerings.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_offering",
        ),
        sa.CheckConstraint("scope_type IN ('course', 'cohort')", name="ck_facilitator_nominations_scope"),
        sa.CheckConstraint("status IN ('pending', 'active', 'revoked')", name="ck_facilitator_nominations_status"),
        sa.CheckConstraint(
            "(scope_type = 'cohort' AND cohort_id IS NOT NULL AND offering_id IS NULL) OR "
            "(scope_type = 'course' AND cohort_id IS NULL AND offering_id IS NOT NULL)",
            name="ck_facilitator_nominations_target",
        ),
    )
    op.create_index("ix_facilitator_nominations_tenant_id", NOMINATIONS, ["tenant_id"])
    op.create_index("ix_facilitator_nominations_person_id", NOMINATIONS, ["person_id"])
    op.create_index("ix_facilitator_nominations_cohort_id", NOMINATIONS, ["cohort_id"])
    op.create_index("ix_facilitator_nominations_offering_id", NOMINATIONS, ["offering_id"])
    op.create_index("ix_facilitator_nominations_status", NOMINATIONS, ["status"])
    op.create_index(
        "uq_facilitator_nominations_cohort_scope",
        NOMINATIONS,
        ["tenant_id", "person_id", "cohort_id"],
        unique=True,
        postgresql_where=sa.text("scope_type = 'cohort'"),
    )
    op.create_index(
        "uq_facilitator_nominations_course_scope",
        NOMINATIONS,
        ["tenant_id", "person_id", "offering_id"],
        unique=True,
        postgresql_where=sa.text("scope_type = 'course'"),
    )

    op.create_table(
        REQUIREMENTS,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("nomination_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("course_id", postgresql.UUID(as_uuid=True), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_facilitator_requirements_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id", "nomination_id", "course_id", name="uq_facilitator_requirements_nomination_course"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "nomination_id"],
            ["facilitator_nominations.tenant_id", "facilitator_nominations.id"],
            ondelete="CASCADE",
            name="fk_facilitator_requirements_nomination",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "course_id"],
            ["courses.tenant_id", "courses.id"],
            name="fk_facilitator_requirements_course",
        ),
    )
    op.create_index("ix_facilitator_requirements_tenant_id", REQUIREMENTS, ["tenant_id"])
    op.create_index("ix_facilitator_requirements_nomination_id", REQUIREMENTS, ["nomination_id"])
    op.create_index("ix_facilitator_requirements_course_id", REQUIREMENTS, ["course_id"])
    _tenant_table(NOMINATIONS)
    _tenant_table(REQUIREMENTS)

    op.execute(
        """
        INSERT INTO facilitator_nominations (
            id, tenant_id, person_id, scope_type, cohort_id, status,
            activated_at, activation_reason, created_at, updated_at
        )
        SELECT gen_random_uuid(), e.tenant_id, e.person_id, 'cohort', e.cohort_id,
               'active', now(), 'legacy_grandfathered', now(), now()
          FROM enrollments e
          JOIN person_roles pr
            ON pr.tenant_id = e.tenant_id AND pr.person_id = e.person_id
          JOIN roles r
            ON r.tenant_id = pr.tenant_id AND r.id = pr.role_id
           AND r.slug = 'instructor'
         WHERE e.role_in_cohort = 'instructor' AND e.status = 'active'
        ON CONFLICT DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_table(REQUIREMENTS)
    op.drop_table(NOMINATIONS)
