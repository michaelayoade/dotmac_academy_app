"""Hosted-only fresh callback canaries; authored, never run locally."""

import pytest
import sqlalchemy as sa

from alembic import command
from app.maintenance import erp_progress_transition as transition
from app.maintenance import fresh_product as fresh
from app.maintenance import product_adoption as product
from app.maintenance import retained_schema as schema
from tests.test_fresh_product_entry_hosted import _actual_application_object as _actual_application_object
from tests.test_fresh_product_entry_hosted import fresh_connection

pytestmark = pytest.mark.usefixtures("_actual_application_object")
assert fresh_connection


@pytest.mark.parametrize(
    ("stage", "sql"),
    [
        ("a004_retained_learning_refs", "ALTER TABLE mod_learning.courses ADD COLUMN unreviewed text"),
        ("a004_retained_learning_refs", "ALTER TABLE public.tenants ADD COLUMN unreviewed text"),
        ("a004_retained_learning_refs", "ALTER INDEX mod_learning.uq_question_banks_tenant_id_id SET (fillfactor=90)"),
        (
            "a005_erp_completion_checkpoint",
            "ALTER TABLE public.academy_erp_completion_checkpoints ADD COLUMN unreviewed text",
        ),
        ("a005_erp_completion_checkpoint", "GRANT SELECT ON public.academy_erp_completion_checkpoints TO app_user"),
        ("a006_lab_claim_lease", "ALTER TABLE mod_learning.courses ADD COLUMN unreviewed text"),
        ("a006_lab_claim_lease", "ALTER TABLE public.lab_operations ALTER COLUMN claim_lease_seconds SET DEFAULT 1"),
        (
            "a006_lab_claim_lease",
            "GRANT EXECUTE ON FUNCTION public.claim_outbox_batch(text,integer,integer) TO app_user",
        ),
        (
            "a006_lab_claim_lease",
            "CREATE OR REPLACE FUNCTION public.claim_outbox_batch(p_worker text,p_batch integer,p_stale_seconds integer) "
            "RETURNS SETOF public.outbox_events LANGUAGE sql SECURITY DEFINER SET search_path='' "
            "AS 'SELECT * FROM public.outbox_events WHERE false'",
        ),
    ],
)
def test_successful_fresh_stage_callback_drift_refuses_before_erp(
    fresh_connection,
    monkeypatch,
    stage,
    sql,
):
    original = command.upgrade
    injected = []

    def upgrade(config, target, *args, **kwargs):
        result = original(config, target, *args, **kwargs)
        if target == stage:
            config.attributes["connection"].execute(sa.text(sql))
            injected.append(stage)
        return result

    monkeypatch.setattr(command, "upgrade", upgrade)
    monkeypatch.setattr(transition, "_consume_fresh_stages", lambda *a: pytest.fail("ERP continuation must not issue"))
    with pytest.raises((fresh.FreshProductRefused, product.ProductAdoptionRefused, schema.RetainedSchemaRefused)):
        fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="ERP-fresh-postcallback-refusal")
    assert injected == [stage]
    assert fresh._issued(fresh_connection).poisoned
    assert fresh_connection.scalar(
        sa.text("SELECT pg_catalog.to_regclass('public.academy_erp_imported_completion_keys') IS NULL")
    )


def test_preexisting_unreferenced_collation_refuses_before_owner_ddl(fresh_connection, monkeypatch):
    fresh_connection.execute(sa.text('CREATE COLLATION public.unreviewed FROM pg_catalog."C"'))
    monkeypatch.setattr(command, "upgrade", lambda *a, **k: pytest.fail("must refuse before owner DDL"))
    with pytest.raises(fresh.FreshProductRefused):
        fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="ERP-unknown-standalone-catalog")
    assert fresh_connection.scalar(sa.text("SELECT pg_catalog.to_regclass('public.alembic_version') IS NULL"))
