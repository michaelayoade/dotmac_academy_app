"""Add Academy progress markers and fixed imported-completion membership.

Only a genuine observed a006 continuation and its exact staged successors may
initialize this provenance. No standalone shape/version-based admission exists.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.maintenance import erp_progress_transition as transition
from app.maintenance import erp_successor_catalog as catalog

revision = "a011_erp_progress_checkpoint"
down_revision = "a010_facilitator_nominations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    entry = transition._consume(connection)
    try:
        rows = catalog.row_evidence(connection, entry.packet)
        op.execute(
            "ALTER TABLE public.academy_erp_completion_checkpoints ADD COLUMN erp_synced_pct double precision NULL"
        )
        op.execute(
            "CREATE TABLE public.academy_erp_imported_completion_keys ("
            "tenant_id uuid NOT NULL,completion_id uuid NOT NULL,"
            "CONSTRAINT academy_erp_imported_completion_keys_pkey PRIMARY KEY (tenant_id,completion_id),"
            "CONSTRAINT academy_erp_imported_completion_keys_tenant_id_fkey FOREIGN KEY (tenant_id) "
            "REFERENCES public.tenants(id) ON DELETE CASCADE,"
            "CONSTRAINT fk_erp_imported_key_tenant_completion FOREIGN KEY (tenant_id,completion_id) "
            "REFERENCES mod_learning.course_completions(tenant_id,id) ON DELETE CASCADE)"
        )
        op.execute("ALTER TABLE public.academy_erp_imported_completion_keys OWNER TO app_admin")
        op.execute("ALTER TABLE public.academy_erp_imported_completion_keys ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE public.academy_erp_imported_completion_keys FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY academy_erp_imported_completion_keys_tenant_isolation "
            "ON public.academy_erp_imported_completion_keys "
            "USING (tenant_id = public.app_current_tenant_id()) "
            "WITH CHECK (tenant_id = public.app_current_tenant_id())"
        )
        for role in (
            "PUBLIC",
            "app_user",
            "platform_api",
            "academy_lab_worker",
            "outbox_dispatcher",
            "platform_outbox_dispatcher",
        ):
            op.execute(sa.text(f"REVOKE ALL ON TABLE public.academy_erp_imported_completion_keys FROM {role}"))
        # Keyset equality was independently established against the retained a005
        # evidence before DDL. This SELECT is custody initialization, never ACK.
        op.execute(
            "INSERT INTO public.academy_erp_imported_completion_keys (tenant_id,completion_id) "
            "SELECT tenant_id,completion_id FROM public.academy_erp_completion_checkpoints"
        )
        transition._record(connection, entry, rows)
    except BaseException:
        transition._poison(connection, entry)
        raise


def downgrade() -> None:
    raise RuntimeError("Academy assembly reversal requires a reviewed new-facts disposition")
