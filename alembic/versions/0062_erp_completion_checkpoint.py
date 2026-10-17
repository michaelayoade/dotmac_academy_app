"""Transfer ERP delivery facts to an Academy-owned product checkpoint.

Online, transactional and unfiltered in both directions. Stop/drain every ERP
sender before upgrade or reversal; the legacy column is an application-frozen
snapshot, not a database permission restriction. See the checkpoint runbook.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import context, op

revision = "0062_erp_completion_checkpoint"
down_revision = "0061_lab_completion_grants"
branch_labels = None
depends_on = None
TABLE = "academy_erp_completion_checkpoints"


def _prepare() -> tuple[str, str]:
    if context.is_offline_mode():
        raise RuntimeError("refusing to generate offline SQL: checkpoint transfer requires live validation")
    bind = op.get_bind()
    previous = (
        bind.execute(sa.text("SHOW row_security")).scalar_one(),
        bind.execute(sa.text("SHOW lock_timeout")).scalar_one(),
    )
    op.execute("SET LOCAL lock_timeout = '5s'")
    # PostgreSQL raises rather than silently filtering when the executing role
    # cannot inspect FORCE-RLS tables without policies. Never bypass by tenant.
    op.execute("SET LOCAL row_security = off")
    return previous


def _restore(previous: tuple[str, str]) -> None:
    for setting, value in zip(("row_security", "lock_timeout"), previous, strict=True):
        op.get_bind().execute(
            sa.text("SELECT set_config(:setting, :value, true)"), {"setting": setting, "value": value}
        )


def _require_equal() -> None:
    mismatch = (
        op.get_bind()
        .execute(
            sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM public.course_completions c
            FULL JOIN public.academy_erp_completion_checkpoints p
              ON p.tenant_id = c.tenant_id AND p.completion_id = c.id
            WHERE c.id IS NULL OR p.completion_id IS NULL
               OR c.erp_synced_at IS DISTINCT FROM p.erp_synced_at
        )
    """)
        )
        .scalar_one()
    )
    if mismatch:
        raise RuntimeError("refusing checkpoint transfer: key or timestamp mismatch")


def upgrade() -> None:
    previous = _prepare()
    op.execute("LOCK TABLE public.course_completions IN ACCESS EXCLUSIVE MODE")
    # Force an unfiltered source read before creating anything.
    op.get_bind().execute(sa.text("SELECT count(*) FROM public.course_completions")).scalar_one()
    op.create_table(
        TABLE,
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("completion_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("erp_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "completion_id"],
            ["public.course_completions.tenant_id", "public.course_completions.id"],
            name="fk_erp_checkpoint_tenant_completion",
            ondelete="CASCADE",
        ),
        schema="public",
    )
    op.execute(
        "INSERT INTO public.academy_erp_completion_checkpoints (tenant_id, completion_id, erp_synced_at) "
        "SELECT tenant_id, id, erp_synced_at FROM public.course_completions"
    )
    _require_equal()
    op.execute("ALTER TABLE public.academy_erp_completion_checkpoints ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.academy_erp_completion_checkpoints FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY academy_erp_completion_checkpoints_tenant_isolation ON public.academy_erp_completion_checkpoints "
        "USING (tenant_id = app_current_tenant_id()) "
        "WITH CHECK (tenant_id = app_current_tenant_id())"
    )
    op.execute("REVOKE ALL ON public.academy_erp_completion_checkpoints FROM PUBLIC, academy_lab_worker")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON public.academy_erp_completion_checkpoints "
        "TO app_user, platform_api, app_admin"
    )
    _restore(previous)


def downgrade() -> None:
    previous = _prepare()
    op.execute(
        "LOCK TABLE public.course_completions, public.academy_erp_completion_checkpoints IN ACCESS EXCLUSIVE MODE"
    )
    conflict = (
        op.get_bind()
        .execute(
            sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM public.course_completions c
            FULL JOIN public.academy_erp_completion_checkpoints p
              ON p.tenant_id = c.tenant_id AND p.completion_id = c.id
            WHERE c.id IS NULL
               OR (c.erp_synced_at IS NOT NULL AND
                   (p.completion_id IS NULL OR c.erp_synced_at IS DISTINCT FROM p.erp_synced_at))
        )
    """)
        )
        .scalar_one()
    )
    if conflict:
        raise RuntimeError("refusing checkpoint reversal: missing reference or conflicting legacy acknowledgement")
    # SQL avoids TimestampMixin.onupdate; NULL is preserved, never coalesced.
    op.execute(
        "UPDATE public.course_completions c SET erp_synced_at = p.erp_synced_at "
        "FROM public.academy_erp_completion_checkpoints p WHERE p.tenant_id = c.tenant_id AND p.completion_id = c.id"
    )
    mismatch = (
        op.get_bind()
        .execute(
            sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM public.academy_erp_completion_checkpoints p
            LEFT JOIN public.course_completions c ON c.tenant_id = p.tenant_id AND c.id = p.completion_id
            WHERE c.id IS NULL OR c.erp_synced_at IS DISTINCT FROM p.erp_synced_at
        )
    """)
        )
        .scalar_one()
    )
    if mismatch:
        raise RuntimeError("refusing checkpoint reversal: verification failed")
    op.drop_table(TABLE, schema="public")
    _restore(previous)
