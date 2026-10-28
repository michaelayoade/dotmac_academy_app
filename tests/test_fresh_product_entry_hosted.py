"""Real hosted fresh-entry convergence/refusals; authored, not run locally.

The sole discovery selector produces unqualified evidence in rolled-back roots.
It never sets the pin, issues a qualified receipt, or commits either database.
"""

import os
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from alembic import command
from app.config import settings
from app.maintenance import fresh_product as fresh
from app.maintenance import product_adoption as product
from app.migration_graph import ordinary_migration_config
from tests import test_academy_lab_claim_lease_adoption as historical
from tests.fixtures.hosted_genesis import hosted_declaration

_actual_application_object = historical._actual_application_object
pytestmark = pytest.mark.usefixtures("_actual_application_object")
assert hosted_declaration


@pytest.fixture
def fresh_connection():
    assert os.environ.get("CI") == os.environ.get("GITHUB_ACTIONS") == "true", "hosted CI only"
    url = os.environ.get("ACADEMY_FRESH_ENTRY_DATABASE_URL")
    assert bool(url), "CI must provision the separate fresh-entry database"
    parsed = make_url(url)
    assert parsed.drivername == "postgresql+psycopg"
    assert parsed.database == "academy_fresh_entry" and parsed.username == "app_admin"
    for name in ("DATABASE_URL", "TEST_DATABASE_URL", "MIGRATION_DATABASE_URL"):
        other = make_url(os.environ[name])
        assert (parsed.host, parsed.port, parsed.database) != (other.host, other.port, other.database)
    engine = sa.create_engine(parsed, hide_parameters=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            root = connection.begin()
            assert connection.scalar(sa.text("SELECT current_user")) == "app_admin"
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c "
                        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')"
                    )
                )
                is True
            )
            try:
                yield connection
            finally:
                if root.is_active:
                    root.rollback()
                if connection.in_transaction():
                    connection.rollback()
    finally:
        engine.dispose()


def test_historical_and_fresh_catalogs_converge(hosted_declaration, fresh_connection, tmp_path, monkeypatch):
    # Historical admission stays genuine, including its population and all three
    # independently sealed historical product transitions.
    with historical._checkpoint_adopted(hosted_declaration, tmp_path, monkeypatch) as (connection, handle):
        product._run_lab_claim_lease_transition(connection, handle)
        cfg = ordinary_migration_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "heads")
        historical_digest = fresh.catalog_fingerprint(connection)
        historical_objects = fresh.catalog_object_digests(connection)
        historical_versions = fresh._versions(connection)
        assert historical_versions == fresh._terminal_versions(fresh._graph())
        fresh._retained_security(connection)
    # The historical fixture declared its genuine postgres/app_admin session;
    # this separate fresh connection has its own actual login/effective roles.
    login, effective = fresh_connection.execute(sa.text("SELECT session_user,current_user")).one()
    monkeypatch.setattr(settings, "migration_login_role", login)
    monkeypatch.setattr(settings, "migration_effective_role", effective)
    root = fresh_connection.get_transaction()
    evidence = fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C4-hosted-convergence-discovery")
    assert type(evidence) is fresh.FreshProductDiscovery
    assert fresh_connection.get_transaction() is root and root.is_active
    fresh_objects = fresh.catalog_object_digests(fresh_connection)
    differences = sorted(
        name
        for name in set(historical_objects) | set(fresh_objects)
        if historical_objects.get(name) != fresh_objects.get(name)
    )
    print(f"Academy unqualified convergence H={historical_digest} F={evidence.catalog_sha256}")
    print("Academy differing catalog names: " + ",".join(differences))
    assert historical_digest == evidence.catalog_sha256
    assert historical_versions == evidence.revisions
    assert not differences
    if fresh.FRESH_CANONICAL_SHA256 is not None:
        assert evidence.catalog_sha256 == fresh.FRESH_CANONICAL_SHA256
    # The discovery evidence never clears the commit fence, even when a pin is
    # present. Commit attempts poison this root; no commit occurs here.
    assert fresh._issued(fresh_connection).commit_guard is not None


@pytest.mark.parametrize("kind", ["legacy", "unknown", "compatibility", "populated"])
def test_real_preparation_refuses_nonempty_or_unknown_targets(fresh_connection, monkeypatch, kind):
    original = fresh.prepare_fresh_product

    def contaminate(connection, *, decision_ref, token_receipt):
        if kind == "legacy":
            connection.execute(sa.text("CREATE TABLE public.people(id uuid)"))
        elif kind == "unknown":
            connection.execute(sa.text("CREATE TABLE public.unreviewed_fresh_relation(id uuid)"))
        elif kind == "compatibility":
            connection.execute(sa.text("CREATE SCHEMA academy_identity_compat"))
        else:
            connection.execute(
                sa.text("INSERT INTO public.tenants(id,slug,name) VALUES (:id,:slug,'test')"),
                {"id": uuid4(), "slug": "fresh-population-refusal"},
            )
        return original(connection, decision_ref=decision_ref, token_receipt=token_receipt)

    monkeypatch.setattr(fresh, "prepare_fresh_product", contaminate)
    with pytest.raises((fresh.FreshProductRefused, sa.exc.DBAPIError)):
        fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C4-hosted-negative")
    assert fresh._issued(fresh_connection).poisoned


@pytest.mark.parametrize("kind", ["counterfeit", "coexistence", "duplicate", "savepoint", "repaired_savepoint", "xid"])
def test_real_issued_continuation_refuses_authority_or_transaction_drift(fresh_connection, monkeypatch, kind):
    original = fresh.prepare_fresh_product

    def contaminate(connection, *, decision_ref, token_receipt):
        if kind == "counterfeit":
            token_receipt = fresh.tokens.AccountTokenIdentityReceipt(
                None,
                token_receipt.token_relation_oid,
                0,
                fresh._A003,
                token_receipt.validated_canonical_foreign_keys,
            )
        elif kind == "coexistence":
            connection.info[product._STATE_KEY] = object()
        elif kind == "duplicate":
            original(connection, decision_ref=decision_ref, token_receipt=token_receipt)
        elif kind == "savepoint":
            connection.begin_nested()
        elif kind == "repaired_savepoint":
            connection.begin_nested().rollback()
        else:
            # Physical rollback invalidates the captured XID even when the
            # SQLAlchemy RootTransaction object has not been replaced.
            connection.connection.driver_connection.rollback()
        return original(connection, decision_ref=decision_ref, token_receipt=token_receipt)

    monkeypatch.setattr(fresh, "prepare_fresh_product", contaminate)
    with pytest.raises((fresh.FreshProductRefused, fresh.identity.IdentityHistoryImportRefused, sa.exc.DBAPIError)):
        fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C4-hosted-negative")
    assert fresh._issued(fresh_connection).poisoned


def test_discovery_cannot_commit_or_reissue(fresh_connection):
    fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C4-hosted-commit-refusal")
    with pytest.raises(fresh.FreshProductRefused, match="not qualified to commit"):
        fresh_connection.commit()
    assert fresh._issued(fresh_connection).poisoned


@pytest.mark.parametrize("kind", ["checkpoint", "function"])
def test_real_extra_runtime_privilege_is_refused(fresh_connection, monkeypatch, kind):
    original = fresh._final_evidence

    def contaminate(connection, graph):
        if kind == "checkpoint":
            connection.execute(sa.text("GRANT SELECT ON public.academy_erp_completion_checkpoints TO app_user"))
        else:
            connection.execute(
                sa.text(
                    "GRANT EXECUTE ON FUNCTION public.activate_eligible_facilitator_nominations"
                    "(uuid,uuid,uuid,uuid,integer,uuid) TO PUBLIC"
                )
            )
        return original(connection, graph)

    monkeypatch.setattr(fresh, "_final_evidence", contaminate)
    with pytest.raises(fresh.FreshProductRefused):
        fresh.rehearse_fresh_composed_entry(fresh_connection, decision_ref="C4-hosted-extra-grant")
    assert fresh._issued(fresh_connection).poisoned


@pytest.fixture
def hostile_catalog_connection(monkeypatch):
    """Rollback-only superuser control for catalog tampering, not role proof.

    The only target is the same provisioned, initially empty fresh-entry DB.
    This never invokes the committing wrapper or issues a qualified receipt.
    """
    assert os.environ.get("CI") == os.environ.get("GITHUB_ACTIONS") == "true", "hosted CI only"
    target = make_url(os.environ["ACADEMY_FRESH_ENTRY_DATABASE_URL"])
    control = make_url(os.environ["KERNEL_ENTRY_DATABASE_URL"])
    assert target.database == "academy_fresh_entry" and target.username == "app_admin"
    assert control.database == "academy_kernel_entry" and control.username == "postgres"
    assert target.drivername == control.drivername == "postgresql+psycopg"
    assert (target.host, target.port) == (control.host, control.port)
    engine = sa.create_engine(control.set(database="academy_fresh_entry"), hide_parameters=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            root = connection.begin()
            assert tuple(connection.execute(sa.text("SELECT session_user,current_user")).one()) == (
                "postgres",
                "postgres",
            )
            assert (
                connection.scalar(sa.text("SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user"))
                is True
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                        "ON n.oid=c.relnamespace WHERE n.nspname='public')"
                    )
                )
                is True
            )
            connection.execute(sa.text("SET LOCAL ROLE app_admin"))
            monkeypatch.setattr(settings, "migration_login_role", "postgres")
            monkeypatch.setattr(settings, "migration_effective_role", "app_admin")
            try:
                yield connection
            finally:
                if root.is_active:
                    root.rollback()
                if connection.in_transaction():
                    connection.rollback()
    finally:
        engine.dispose()


@pytest.mark.parametrize("change", ["function_default", "disabled_parent_ri"])
def test_hosted_fingerprint_detects_function_defaults_and_live_fk_enforcement(hostile_catalog_connection, change):
    connection = hostile_catalog_connection
    evidence = fresh.rehearse_fresh_composed_entry(connection, decision_ref="C4-hostile-catalog-projection")
    assert type(evidence) is fresh.FreshProductDiscovery
    before = fresh._catalog_packet(connection)
    if change == "function_default":
        definition = connection.scalar(
            sa.text(
                "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure("
                "'public.activate_eligible_facilitator_nominations(uuid,uuid,uuid,uuid,integer,uuid)'))"
            )
        )
        fragment = "p_limit integer DEFAULT NULL::integer"
        assert definition.count(fragment) == 1
        connection.exec_driver_sql(definition.replace(fragment, "p_limit integer DEFAULT 1", 1))
    else:
        # Select a real parent-side internal trigger. ALTER succeeds only under
        # explicit superuser test control; permission denial does not pass.
        trigger = connection.scalar(
            sa.text(
                "SELECT t.tgname FROM pg_catalog.pg_trigger t "
                "JOIN pg_catalog.pg_constraint k ON k.oid=t.tgconstraint "
                "WHERE t.tgrelid='public.tenants'::regclass AND t.tgisinternal AND k.contype='f' "
                "AND k.conrelid='public.applicants'::regclass ORDER BY t.tgname LIMIT 1"
            )
        )
        assert trigger is not None
        quoted = connection.dialect.identifier_preparer.quote(trigger)
        connection.execute(sa.text("SET LOCAL ROLE postgres"))
        connection.exec_driver_sql('ALTER TABLE "public"."tenants" DISABLE TRIGGER ' + quoted)
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_catalog.pg_trigger "
                    "WHERE tgrelid='public.tenants'::regclass AND tgname=:name AND tgenabled='D'"
                ),
                {"name": trigger},
            )
            == 1
        )
    after = fresh._catalog_packet(connection)
    changed = sorted(key for key in before if before[key] != after[key])
    assert changed == (["functions"] if change == "function_default" else ["ri_triggers"])
    assert fresh.catalog_fingerprint(connection) != evidence.catalog_sha256
    assert fresh._issued(connection).commit_guard is not None
    # Missing-only internal rows are covered by the no-DB projection regression.
    # DROP TRIGGER is FK-dependency protected; no direct pg_catalog writes here.
