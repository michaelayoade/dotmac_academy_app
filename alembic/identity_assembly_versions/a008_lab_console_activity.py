"""Add `lab_console_activity` — console-use heartbeat that keeps a lab alive.

The idle reaper (`lab_jobs.request_idle_reaps`) measured idleness from
`lab_instances.last_active_at`, which only launch, reset and Run checks move,
so a learner typing in a console was reaped after `lab_idle_minutes`.

The web tier deliberately cannot UPDATE `lab_instances` (0056: runtime state is
worker-owned), and this migration keeps that boundary intact. Instead the web
tier records its own observation in this small side table, one row per
instance, and the reaper (a policy reader running as the offline admin role)
takes `greatest(last_active_at, last_seen_at)`. The web role gets exactly:
SELECT, INSERT of (instance_id, tenant_id, last_seen_at) and UPDATE of
(last_seen_at). No DELETE, no other column, and the lab worker and
platform_api get nothing. Row-level security follows the tenant isolation
pattern of the other lab tables, and the composite FK to `lab_instances`
cascades so a deleted instance leaves no row behind.

`last_seen_at` is never trusted from the client: a BEFORE INSERT OR UPDATE
trigger overwrites it with the database clock. Without it the web role could
store a far-future timestamp and keep a lab from ever being reaped (and clock
skew between web hosts could do the same by accident).

Revision ID: a008_lab_console_activity
Revises: a007_lab_template_access
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a008_lab_console_activity"
down_revision = "a007_lab_template_access"
branch_labels = None
depends_on = None

TABLE = "lab_console_activity"


def upgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT current_user")) != "app_admin":
        raise ValueError("Academy assembly migration requires app_admin")
    if op.get_bind().scalar(sa.text("""
        SELECT pg_catalog.to_regclass('public.lab_console_activity') IS NOT NULL
          OR pg_catalog.to_regclass('public.ix_lab_console_activity_tenant_id') IS NOT NULL
          OR pg_catalog.to_regprocedure('public.lab_console_activity_stamp()') IS NOT NULL
    """)):
        raise ValueError("lab console activity objects already exist")
    op.create_table(
        TABLE,
        sa.Column("instance_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "instance_id"],
            ["public.lab_instances.tenant_id", "public.lab_instances.id"],
            name="fk_lab_console_activity_instance",
            ondelete="CASCADE",
        ),
        schema="public",
    )
    op.create_index("ix_lab_console_activity_tenant_id", TABLE, ["tenant_id"], schema="public")
    op.execute(f"ALTER TABLE public.{TABLE} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE public.{TABLE} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {TABLE}_tenant_isolation ON public.{TABLE} "
        f"USING (tenant_id = public.app_current_tenant_id()) "
        f"WITH CHECK (tenant_id = public.app_current_tenant_id());"
    )
    op.execute(
        "CREATE FUNCTION public.lab_console_activity_stamp() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog AS $$ "
        "BEGIN NEW.last_seen_at := pg_catalog.now(); RETURN NEW; END; $$;"
    )
    op.execute(
        f"CREATE TRIGGER {TABLE}_stamp BEFORE INSERT OR UPDATE ON public.{TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION public.lab_console_activity_stamp();"
    )
    op.execute(f"REVOKE ALL PRIVILEGES ON public.{TABLE} FROM PUBLIC;")
    op.execute(f"GRANT SELECT ON public.{TABLE} TO app_user;")
    op.execute(f"GRANT INSERT (instance_id, tenant_id, last_seen_at) ON public.{TABLE} TO app_user;")
    op.execute(f"GRANT UPDATE (last_seen_at) ON public.{TABLE} TO app_user;")



def downgrade() -> None:
    raise RuntimeError("Academy assembly reversal requires a reviewed new-facts disposition")
