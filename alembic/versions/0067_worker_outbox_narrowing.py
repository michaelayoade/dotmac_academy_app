"""Narrow the lab worker's email_outbox SELECT to the conflict-key columns.

Revision ID: 0067_worker_outbox_narrowing
Revises: 0066_erp_completion_checkpoint

Neutral codification of the 2026-11-06 production hotfix: the three
statements below are natively idempotent, so this migration is a no-op on a
database where the hotfix was already applied. The worker keeps the three
column SELECTs its ``INSERT ... ON CONFLICT (tenant_id, idempotency_key)
DO NOTHING RETURNING id`` requires; it loses the table-wide SELECT that let
it read every tenant's recipient, subject and raw token-link bodies.

Also pins the 0064 definer's ``search_path`` to ``pg_catalog, pg_temp``
(pg_temp explicitly last, so a session-local pg_temp type can never shadow a
system type).

The downgrade is the exact reverse. Its unpin of the 0064 ``search_path``
back to ``pg_catalog`` alone is an explicit RE-WIDENING of that pg_temp
type-shadowing weakness (R1) — downgrade restores the weakness knowingly.
"""

from __future__ import annotations

from alembic import op

revision = "0067_worker_outbox_narrowing"
down_revision = "0066_erp_completion_checkpoint"
branch_labels = None
depends_on = None

ACTIVATION_CAPABILITY = "public.activate_eligible_facilitator_nominations(uuid, uuid, uuid, uuid, integer, uuid)"


def upgrade() -> None:
    op.execute("REVOKE SELECT ON TABLE public.email_outbox FROM academy_lab_worker;")
    op.execute("GRANT SELECT (id, tenant_id, idempotency_key) " "ON TABLE public.email_outbox TO academy_lab_worker;")
    op.execute(f"ALTER FUNCTION {ACTIVATION_CAPABILITY} SET search_path = pg_catalog, pg_temp;")


def downgrade() -> None:
    op.execute(f"ALTER FUNCTION {ACTIVATION_CAPABILITY} SET search_path = pg_catalog;")
    op.execute(
        "REVOKE SELECT (id, tenant_id, idempotency_key) " "ON TABLE public.email_outbox FROM academy_lab_worker;"
    )
    op.execute("GRANT SELECT ON TABLE public.email_outbox TO academy_lab_worker;")
