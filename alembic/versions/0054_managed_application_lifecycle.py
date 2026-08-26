"""Academy-owned managed application lifecycle execution evidence.

Revision ID: 0054_managed_app_lifecycle
Revises: 0053_entrance_defaults
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0054_managed_app_lifecycle"
down_revision = "0053_entrance_defaults"
branch_labels = None
depends_on = None

_TABLE = "managed_application_lifecycle_operations"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=120), nullable=False),
        sa.Column("target", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("target_digest", sa.String(length=71), nullable=False),
        sa.Column("expected_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("expected_state_digest", sa.String(length=71), nullable=False),
        sa.Column("plan_digest", sa.String(length=71), nullable=False),
        sa.Column("desired_state", sa.String(length=20), nullable=False),
        sa.Column("operation_state", sa.String(length=20), nullable=False, server_default="planned"),
        sa.Column("result_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("result_state_digest", sa.String(length=71), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_managed_application_lifecycle_operations"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_managed_application_lifecycle_tenant_idempotency",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_managed_application_lifecycle_tenant_id",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="RESTRICT",
            name="fk_managed_application_lifecycle_tenant_person",
        ),
        sa.CheckConstraint(
            "desired_state IN ('active', 'suspended')",
            name="ck_managed_application_lifecycle_desired_state",
        ),
        sa.CheckConstraint(
            "operation_state IN ('planned', 'applied', 'cancelled')",
            name="ck_managed_application_lifecycle_operation_state",
        ),
        sa.CheckConstraint(
            "target_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_managed_application_lifecycle_target_digest",
        ),
        sa.CheckConstraint(
            "expected_state_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_managed_application_lifecycle_expected_digest",
        ),
        sa.CheckConstraint(
            "plan_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_managed_application_lifecycle_plan_digest",
        ),
        sa.CheckConstraint(
            "result_state_digest IS NULL OR result_state_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_managed_application_lifecycle_result_digest",
        ),
        sa.CheckConstraint(
            "(operation_state = 'planned' AND applied_at IS NULL AND cancelled_at IS NULL "
            "AND result_state IS NULL AND result_state_digest IS NULL) OR "
            "(operation_state = 'applied' AND applied_at IS NOT NULL AND cancelled_at IS NULL "
            "AND result_state IS NOT NULL AND result_state_digest IS NOT NULL) OR "
            "(operation_state = 'cancelled' AND applied_at IS NULL AND cancelled_at IS NOT NULL "
            "AND result_state IS NULL AND result_state_digest IS NULL)",
            name="ck_managed_application_lifecycle_state_shape",
        ),
    )
    op.create_index(
        "ix_managed_application_lifecycle_operations_tenant_id",
        _TABLE,
        ["tenant_id"],
    )
    op.create_index(
        "ix_managed_application_lifecycle_operations_person_id",
        _TABLE,
        ["person_id"],
    )

    op.execute(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {_TABLE}_tenant_isolation ON {_TABLE} "
        "USING (tenant_id = app_current_tenant_id()) "
        "WITH CHECK (tenant_id = app_current_tenant_id());"
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO app_user, platform_api;")

    # The PLAN is an authorization input.  Its exact target and state pins may
    # never be rewritten into a different plan after an approval references it.
    op.execute(
        """
        CREATE FUNCTION academy_managed_lifecycle_plan_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
               OR NEW.person_id IS DISTINCT FROM OLD.person_id
               OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
               OR NEW.target IS DISTINCT FROM OLD.target
               OR NEW.target_digest IS DISTINCT FROM OLD.target_digest
               OR NEW.expected_state IS DISTINCT FROM OLD.expected_state
               OR NEW.expected_state_digest IS DISTINCT FROM OLD.expected_state_digest
               OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
               OR NEW.desired_state IS DISTINCT FROM OLD.desired_state THEN
                RAISE EXCEPTION 'managed application lifecycle plan fields are immutable';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        f"CREATE TRIGGER trg_{_TABLE}_plan_immutable "
        f"BEFORE UPDATE ON {_TABLE} FOR EACH ROW "
        "EXECUTE FUNCTION academy_managed_lifecycle_plan_immutable();"
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS trg_{_TABLE}_plan_immutable ON {_TABLE};")
    op.execute("DROP FUNCTION IF EXISTS academy_managed_lifecycle_plan_immutable();")
    op.execute(f"DROP POLICY IF EXISTS {_TABLE}_tenant_isolation ON {_TABLE};")
    op.drop_table(_TABLE)
