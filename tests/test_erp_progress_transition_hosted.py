"""Hosted-only fresh callback canaries; authored, never run locally."""

import pytest
import sqlalchemy as sa

from alembic import command
from app.maintenance import erp_progress_transition as transition
from app.maintenance import fresh_product as fresh
from app.maintenance import product_adoption as product
from app.maintenance import retained_schema as schema
from tests.test_fresh_product_entry_hosted import _actual_application_object as _actual_application_object
from tests.test_fresh_product_entry_hosted import fresh_connection, hosted_declaration

pytestmark = pytest.mark.usefixtures("_actual_application_object")
assert fresh_connection and hosted_declaration


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


def test_actual_pg16_raw_catalog_representation_and_all_real_successor_stages(fresh_connection, monkeypatch):
    """Read-only catalog wire evidence beneath genuine replay; no printed rows."""
    import json

    catalog = transition.catalog
    original = catalog.validate_stage
    observations = []

    def validate(connection, before, after, stage, **kwargs):
        result = original(connection, before, after, stage, **kwargs)
        if stage == "a007_lab_template_access":
            # Fixed catalog names only. pg_attrdef has the genuine a007 default;
            # global catalog samples include builtin rewrite/type/proc objects.
            samples = {}
            for category in (
                "pg_class",
                "pg_type",
                "pg_constraint",
                "pg_attrdef",
                "pg_policy",
                "pg_trigger",
                "pg_index",
                "pg_proc",
                "pg_rewrite",
            ):
                identity = "indexrelid" if category == "pg_index" else "oid"
                key, raw = connection.execute(
                    sa.text(
                        f"SELECT x.{identity},pg_catalog.to_jsonb(x)::text FROM pg_catalog.{category} x ORDER BY x.{identity} LIMIT 1"  # noqa: S608 -- fixed source tuple above
                    )
                ).one()
                samples[category] = json.loads(raw)
                decoded = catalog._catalog_view(category, key, raw)
                assert type(decoded["indexrelid" if category == "pg_index" else "oid"]) is int
            key, number, raw = connection.execute(
                sa.text(
                    "SELECT x.attrelid,x.attnum,pg_catalog.to_jsonb(x)::text FROM pg_catalog.pg_attribute x "
                    "ORDER BY x.attrelid,x.attnum LIMIT 1"
                )
            ).one()
            attribute = json.loads(raw)
            catalog._catalog_view("pg_attribute", (key, number), raw)
            assert type(attribute["attrelid"]) is str and type(attribute["attnum"]) is int
            assert type(samples["pg_class"]["relowner"]) is str
            assert type(samples["pg_attrdef"]["adrelid"]) is str
            assert all(type(item) is str for item in samples["pg_index"]["indclass"])
            assert all(type(item) is int for item in samples["pg_index"]["indkey"])
            assert all(type(item) is str for item in samples["pg_proc"]["proargtypes"])
            assert type(samples["pg_proc"]["prosupport"]) is str
            # The separate native query deliberately requests the numeric OID.
            support = connection.scalar(
                sa.text("SELECT p.prosupport::oid FROM pg_catalog.pg_proc p ORDER BY p.oid LIMIT 1")
            )
            assert type(support) is int
        observations.append(stage)
        return result

    monkeypatch.setattr(catalog, "validate_stage", validate)
    evidence = fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C42-PG16-wire-discovery")
    assert type(evidence) is fresh.FreshProductDiscovery
    assert observations == [*transition._STAGES, transition._A011]


@pytest.mark.parametrize(
    "stage,statement",
    [
        ("a007_lab_template_access", "ALTER TABLE public.lab_templates ALTER COLUMN access SET DEFAULT '{}'::jsonb"),
        ("a008_lab_console_activity", "CREATE INDEX c42_unexpected_index ON public.lab_console_activity(last_seen_at)"),
        (
            "a009_applicant_bank_version_pin",
            "GRANT UPDATE(assessment_bank_version_id) ON public.applicants TO app_user",
        ),
    ],
)
def test_real_successor_stage_wire_decoding_does_not_hide_actual_catalog_drift(
    fresh_connection, monkeypatch, stage, statement
):
    original = transition.catalog.validate_stage
    attacked = []

    def validate(connection, before, after, target, **kwargs):
        # Genuine complete stage succeeds before tamper, including real raw
        # validation; rebuilding after tamper exercises the actual observer.
        result = original(connection, before, after, target, **kwargs)
        if target == stage:
            connection.execute(sa.text(statement))
            attacked.append(target)
            return original(connection, before, transition.catalog.observe(connection), target, **kwargs)
        return result

    monkeypatch.setattr(transition.catalog, "validate_stage", validate)
    with pytest.raises((fresh.FreshProductRefused, product.ProductAdoptionRefused, schema.RetainedSchemaRefused)):
        fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C42-raw-catalog-drift")
    assert attacked == [stage]
    assert fresh._issued(fresh_connection).poisoned


def _c44_dead_versions_before_capture(monkeypatch):
    from tests.fixtures import product_adoption_entry as entry

    populate = entry._populate_retained

    def with_dead_versions(connection):
        populate(connection)
        assert connection.execute(sa.text("UPDATE public.applicants SET notes=notes")).rowcount > 0
        connection.execute(
            sa.text(
                "INSERT INTO public.applicants(id,tenant_id,email,first_name,last_name) "
                "SELECT gen_random_uuid(),tenant_id,'c44-dead@example.invalid','Dead','Version' "
                "FROM public.applicants LIMIT 1"
            )
        )
        assert (
            connection.execute(sa.text("DELETE FROM public.applicants WHERE email='c44-dead@example.invalid'")).rowcount
            == 1
        )
        assert connection.scalar(sa.text("SELECT count(*) FROM ONLY public.applicants")) > 0

    monkeypatch.setattr(entry, "_populate_retained", with_dead_versions)


def test_genuine_historical_a009_heap_live_count_ignores_own_dead_versions(hosted_declaration, tmp_path, monkeypatch):
    from tests import test_academy_lab_claim_lease_adoption as historical

    _c44_dead_versions_before_capture(monkeypatch)
    original = transition.catalog._verify_a009_heap_statistics
    observed = []

    def verify(connection, before, after, original_rows):
        result = original(connection, before, after, original_rows)
        count = connection.scalar(sa.text("SELECT count(*) FROM ONLY public.applicants"))
        assert count > 0 and result is not None
        observed.append(count)
        return result

    monkeypatch.setattr(transition.catalog, "_verify_a009_heap_statistics", verify)
    with historical._checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        root = connection.get_transaction()
        product._run_lab_claim_lease_transition(connection, handle)
        product._run_erp_progress_transition(connection, handle)
        assert observed and len(observed) == 1
        assert connection.get_transaction() is root and root.is_active
        assert not product._state_for(handle).poisoned
    # Existing genuine qualified_root rollback oracle checks full public source
    # restoration and removal of canonical DDL after this disposable root.


def test_genuine_empty_fresh_a009_checks_empty_heap_statistics(fresh_connection, monkeypatch):
    import json

    original = transition.catalog._verify_a009_heap_statistics
    observed = []

    def verify(connection, before, after, original_rows):
        result = original(connection, before, after, original_rows)
        assert connection.scalar(sa.text("SELECT count(*) FROM ONLY public.applicants")) == 0
        old = next(json.loads(raw) for raw in before["pg_class"].values() if json.loads(raw)["relname"] == "applicants")
        assert (result is None) is (old["reltuples"] < 0)
        observed.append(True)
        return result

    monkeypatch.setattr(transition.catalog, "_verify_a009_heap_statistics", verify)
    root = fresh_connection.get_transaction()
    evidence = fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C44-empty-index-statistics")
    assert type(evidence) is fresh.FreshProductDiscovery and observed == [True]
    assert fresh_connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize("attack", ["pages", "tuples", "applicant_options", "unrelated", "late_raw"])
def test_hostile_historical_catalog_fixture_cannot_rebase_a009_statistics(
    hosted_declaration, tmp_path, monkeypatch, attack
):
    """Privileged hostile-catalog fixture, NOT role/authorization proof; unrun."""
    from tests import test_academy_lab_claim_lease_adoption as historical
    from tests import test_academy_product_adoption as product_tests

    # Augment the existing same-resource rollback oracle with the two raw heap
    # statistics, proving this privileged injection is transactionally restored.
    footprint = product_tests.public_footprint

    def including_statistics(connection):
        stats = connection.execute(
            sa.text("SELECT relpages,reltuples FROM pg_catalog.pg_class WHERE oid='public.applicants'::regclass")
        ).one()
        return footprint(connection), tuple(stats)

    monkeypatch.setattr(product_tests, "public_footprint", including_statistics)
    actual = transition.catalog._verify_a009_heap_statistics
    injected = []

    def hostile(connection, before, after, original_rows):
        root = connection.get_transaction()
        context = transition.tokens._physical_context(connection)
        assert connection.execute(sa.text("SELECT session_user,current_user")).one() == ("postgres", "app_admin")
        actual(connection, before, after, original_rows)
        if attack in ("pages", "tuples"):
            # Sole privileged mutation: the fixed heap's two source statistics.
            connection.execute(sa.text("SET LOCAL ROLE postgres"))
            try:
                statement = (
                    "UPDATE pg_catalog.pg_class SET relpages=relpages+1 WHERE oid='public.applicants'::regclass"
                    if attack == "pages"
                    else "UPDATE pg_catalog.pg_class SET reltuples=reltuples+1 WHERE oid='public.applicants'::regclass"
                )
                assert connection.execute(sa.text(statement)).rowcount == 1
            finally:
                connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        elif attack == "unrelated":
            connection.execute(sa.text("ALTER TABLE public.lab_templates SET (fillfactor=80)"))
        else:
            connection.execute(sa.text("ALTER TABLE public.applicants SET (fillfactor=80)"))
        assert connection.scalar(sa.text("SELECT current_user")) == "app_admin"
        assert connection.get_transaction() is root and root.is_active
        assert transition.tokens._physical_context(connection) == context
        injected.append(True)
        if attack != "late_raw":
            observed = transition.catalog.observe(connection)
            appended = set(observed["pg_attribute"]) - set(before["pg_attribute"])
            # Re-run the genuine local comparison against the newly observed
            # hostile packet; the helper itself retains its production contract.
            with monkeypatch.context() as context_patch:
                context_patch.setattr(transition.catalog, "_verify_a009_heap_statistics", actual)
                transition.catalog.conserve(
                    before,
                    observed,
                    stage="a009_applicant_bank_version_pin",
                    appended=appended,
                    connection=connection,
                    original_rows=original_rows,
                )
            pytest.fail("hostile catalog comparison unexpectedly accepted")
        actual(connection, before, after, original_rows)
        pytest.fail("late raw catalog mutation unexpectedly accepted")

    monkeypatch.setattr(transition.catalog, "_verify_a009_heap_statistics", hostile)
    with historical._checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_lab_claim_lease_transition(connection, handle)
        with pytest.raises((product.ProductAdoptionRefused, schema.RetainedSchemaRefused)):
            product._run_erp_progress_transition(connection, handle)
        assert injected == [True] and product._state_for(handle).poisoned
        assert transition._KEY not in connection.info
