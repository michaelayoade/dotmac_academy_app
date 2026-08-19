"""Add learner course access request overrides."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0054_course_access_requests"
down_revision = "0053_entrance_defaults"
branch_labels = None
depends_on = None


def _ts() -> list:
    return [
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    ]


def _rls(table_name: str) -> None:
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {table_name}_tenant_isolation ON {table_name} "
        f"USING (tenant_id = app_current_tenant_id()) "
        f"WITH CHECK (tenant_id = app_current_tenant_id());"
    )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table_name} "
        "TO app_user, platform_api;"
    )


def upgrade() -> None:
    op.create_table(
        "course_access_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("course_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("requested_reason", sa.Text(), nullable=True),
        sa.Column("reviewed_by_person_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_reason", sa.Text(), nullable=True),
        *(
            _ts()
        ),
        sa.UniqueConstraint("tenant_id", "person_id", "course_id", name="uq_course_access_requests_tenant_person_course"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_course_access_requests_tenant_person",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "course_id"],
            ["courses.tenant_id", "courses.id"],
            ondelete="CASCADE",
            name="fk_course_access_requests_tenant_course",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reviewed_by_person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="SET NULL",
            name="fk_course_access_requests_tenant_reviewer",
        ),
    )
    op.create_index("ix_course_access_requests_tenant_id", "course_access_requests", ["tenant_id"])
    op.create_index("ix_course_access_requests_person_id", "course_access_requests", ["person_id"])
    op.create_index("ix_course_access_requests_course_id", "course_access_requests", ["course_id"])
    op.create_index(
        "ix_course_access_requests_status", "course_access_requests", ["status"]
    )
    _rls("course_access_requests")


def downgrade() -> None:
    op.drop_index("ix_course_access_requests_status", table_name="course_access_requests")
    op.drop_index("ix_course_access_requests_course_id", table_name="course_access_requests")
    op.drop_index("ix_course_access_requests_person_id", table_name="course_access_requests")
    op.drop_index("ix_course_access_requests_tenant_id", table_name="course_access_requests")
    op.drop_table("course_access_requests")
