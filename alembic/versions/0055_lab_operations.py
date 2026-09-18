"""Add `lab_operations` — the durable work queue a lab worker will claim from.

Phase 1 of the lab-worker-ownership design (Knowledge slug
`academy-lab-worker-ownership-design-2026-09-18`): schema only. Nothing reads
or writes this table yet. `kind` and `state` are deliberately left without a
DB CHECK constraint — the enum of valid values is still settling and a later
migration will add the constraint once a worker actually exists to honor it.
`requested_by` is deliberately not a declared FK to `people` yet, for the same
reason.

The load-bearing invariant of this whole design lives in the grants, not the
columns: `app_user`/`platform_api` get SELECT (+INSERT for `app_user`, so the
web tier can request an operation and observe it) but neither gets UPDATE or
DELETE. Only `app_admin` (already BYPASSRLS/table owner) can settle a row —
the web tier can never mark its own request as claimed, succeeded, or failed.

The partial unique index `uq_lab_operations_open_per_instance` is the other
half: at most one `queued` or `claimed` operation may exist per instance at a
time, so a second deploy/destroy/check request for the same instance is
rejected at the database rather than racing an in-flight one.

Revision ID: 0055_lab_operations
Revises: 0054_lab_instructions_md
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0055_lab_operations"
down_revision = "0054_lab_instructions_md"
branch_labels = None
depends_on = None

TABLE = "lab_operations"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("claimed_by", sa.String(200), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id", "instance_id"],
                                ["lab_instances.tenant_id", "lab_instances.id"],
                                ondelete="CASCADE",
                                name="fk_lab_operations_tenant_instance"),
    )
    op.create_index(
        "uq_lab_operations_open_per_instance",
        TABLE,
        ["instance_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('queued', 'claimed')"),
    )
    op.create_index("ix_lab_operations_claim", TABLE, ["state", "not_before", "requested_at"])
    op.create_index("ix_lab_operations_tenant_id", TABLE, ["tenant_id"])

    op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {TABLE}_tenant_isolation ON {TABLE} "
        f"USING (tenant_id = app_current_tenant_id()) "
        f"WITH CHECK (tenant_id = app_current_tenant_id());"
    )
    # Deliberately no UPDATE/DELETE for app_user or platform_api: the web tier
    # may request and observe an operation, never settle one. Only app_admin
    # (BYPASSRLS/table owner already) may claim, heartbeat, or finish a row.
    op.execute(f"GRANT SELECT, INSERT ON {TABLE} TO app_user;")
    op.execute(f"GRANT SELECT ON {TABLE} TO platform_api;")


def downgrade() -> None:
    op.drop_table(TABLE)
