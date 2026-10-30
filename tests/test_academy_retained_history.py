"""Hosted digest/conservation canaries; AUTHORED, NOT RUN.

Genuine frozen62 populated replay only. Observation comparisons below create no
admission. Genuine capture requires actual Schema and hosted Environment gates.
"""

import json
import os

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import make_url

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import retained_environment as environment
from app.maintenance import retained_history as history
from app.maintenance import retained_schema as retained
from tests.fixtures.hosted_genesis import hosted_declaration, qualified_root, replayed_owner
from tests.fixtures.kernel_identity_entry.rehearsal import FIXTURE, LEGACY_HEAD, config_for, verify_legacy_source
from tests.test_kernel_identity_entry import _seed_populated_legacy, entry_transaction

__all__ = ["hosted_declaration"]


@pytest.fixture(scope="module")
def retained_history_engine(tmp_path_factory):
    """Own a NEW dedicated empty profile database; never reuse retained_engine.

    Next root-owned CI slice must provision this separately. A module-scoped
    import of retained_engine would initialize its same database twice during
    full collection. No populated fallback, environment mutation or skip.
    """
    assert os.environ.get("CI") == "true", "environment profile rehearsals are hosted CI only"
    url = os.environ.get("RETAINED_HISTORY_DATABASE_URL")
    assert url, "CI must separately provision RETAINED_HISTORY_DATABASE_URL"
    target = make_url(url)
    assert target.get_backend_name() == "postgresql" and target.database
    for name in (
        "RETAINED_SCHEMA_DATABASE_URL",
        "RETAINED_ENVIRONMENT_DATABASE_URL",
        "KERNEL_ENTRY_DATABASE_URL",
        "TEST_DATABASE_URL",
        "TEST_MIGRATION_DATABASE_URL",
        "MIGRATION_DATABASE_URL",
        "DATABASE_URL",
        "TEST_LAB_WORKER_DATABASE_URL",
        "PLATFORM_DATABASE_URL",
    ):
        other = os.environ.get(name)
        if other:
            assert target.database != make_url(other).database, "profile replay DB must be separate"
    verify_legacy_source()
    retained._verify_frozen_source(FIXTURE / "alembic/versions")
    engine = sa.create_engine(url, hide_parameters=True, echo=False, future=True)
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.text("""
                SELECT count(*) FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
            """)
                )
                == 0
            ), "profile replay DB must start genuinely empty"
            assert (
                connection.scalar(
                    sa.text("""
                SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN
                ('app_admin','app_user','platform_api','academy_lab_worker',
                 'outbox_dispatcher','platform_outbox_dispatcher')
            """)
                )
                == 6
            ), "CI must provision genuine unchanged cluster roles"
            connection.rollback()
            with connection.begin():
                connection.execute(sa.text("SET ROLE app_admin"))
            applied = []
            cfg = config_for(
                connection, FIXTURE / "alembic/versions", tmp_path_factory.mktemp("retained-history-entry-env"), applied
            )
            scripts = ScriptDirectory.from_config(cfg)
            assert scripts.get_heads() == [LEGACY_HEAD]
            command.upgrade(cfg, "heads")
            assert len(applied) == 62
            assert {item.revision for item in applied} == {item.revision for item in scripts.walk_revisions()}
            assert not connection.in_transaction()
            with connection.begin():
                _seed_populated_legacy(connection)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def history_bindings():
    assert os.environ.get("CI") == "true"
    declared = os.environ.get("ACADEMY_RETAINED_HISTORY_BINDINGS")
    assert declared, "CI must provide explicit non-secret expected environment bindings"
    values = json.loads(declared)
    key = "academy_retained_environment_extension_versions"
    values[key] = tuple(tuple(item) for item in values[key])
    bindings = environment.bindings_from_settings(values)
    assert bindings.target_database == make_url(os.environ["RETAINED_HISTORY_DATABASE_URL"]).database
    return bindings


def _populate_retained(connection):
    # Real frozen schema, native server payloads; no credentials enter Python.
    tenant, person, course = connection.execute(
        sa.text("""
        SELECT p.tenant_id,p.id,c.id FROM public.people p
        JOIN public.courses c ON c.tenant_id=p.tenant_id ORDER BY p.id LIMIT 1
    """)
    ).one()
    params = {"tenant": tenant, "person": person, "course": course}
    for statement in (
        "INSERT INTO public.applicants(id,tenant_id,email,first_name,last_name) "
        "VALUES(gen_random_uuid(),:tenant,'digest@example.invalid','Digest','Canary')",
        "INSERT INTO public.email_outbox(id,tenant_id,idempotency_key,recipient,subject,html_body) "
        "VALUES(gen_random_uuid(),:tenant,'digest','digest@example.invalid','Digest','<p>Digest</p>')",
        "INSERT INTO public.lab_instances(id,tenant_id,activity_id,person_id,instance_name) "
        "VALUES(gen_random_uuid(),:tenant,gen_random_uuid(),:person,'digest')",
        "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind) "
        "SELECT gen_random_uuid(),tenant_id,id,'check' FROM public.lab_instances WHERE tenant_id=:tenant",
        "INSERT INTO public.lab_templates(id,tenant_id,course_id,activity_id,slug,title) "
        "VALUES(gen_random_uuid(),:tenant,:course,gen_random_uuid(),'digest','Digest')",
        "INSERT INTO public.notifications(id,tenant_id,person_id,kind,title) "
        "VALUES(gen_random_uuid(),:tenant,:person,'digest','Digest')",
        "INSERT INTO public.onboarding_tasks(id,tenant_id,applicant_id,key,label) "
        "SELECT gen_random_uuid(),tenant_id,id,'digest','Digest' FROM public.applicants WHERE tenant_id=:tenant",
        "INSERT INTO public.platform_settings(key,value) VALUES('digest-canary',NULL)",
        "INSERT INTO public.reminder_log(id,tenant_id,person_id,event_kind,occurrence_key) "
        "VALUES(gen_random_uuid(),:tenant,:person,'digest','digest')",
        "INSERT INTO public.reminder_preferences(id,tenant_id,person_id) " "VALUES(gen_random_uuid(),:tenant,:person)",
        "INSERT INTO public.tenant_entrance_defaults(tenant_id) VALUES(:tenant)",
    ):
        connection.execute(sa.text(statement), params)
    for name, _, _ in history._ROW_SPEC:
        connection.execute(sa.text(f'LOCK TABLE public."{name}" IN ACCESS EXCLUSIVE MODE'))


def _applicant_digest(connection):
    rows = connection.execute(sa.text(history._row_query("applicants"))).all()
    assert len(rows) == 1
    return rows[0][1]


def test_fixed_all166_cells_and_genuine_capture_refuses_without_issued_state(retained_history_engine, history_bindings):
    assert len(history._ROW_SPEC) == 11
    assert sum(len(columns) for _, _, columns in history._ROW_SPEC) == 166
    assert tuple((name, tuple(columns)) for name, _, columns in history._ROW_SPEC) == tuple(
        (name, tuple((column, sql_type) for column, sql_type, _, _ in columns)) for name, columns in retained._COLUMNS
    )
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        before_info = dict(connection.info)
        before = history._observe_rows(connection)
        assert all(table.rows for table in before)
        assert retained._verify_historical_retained_schema(connection) is None
        with pytest.raises(environment.RetainedEnvironmentUnsupported):
            history._capture_retained_rows(connection, history_bindings)
        assert dict(connection.info) == before_info
        assert history._observe_rows(connection) == before
        # Fixed Schema now passes; absence of a live hosted owner still refuses
        # before fragment construction. Real Environment is called independently.
        with pytest.raises(environment.RetainedEnvironmentUnsupported):
            environment.observe_retained_environment(connection, history_bindings)


def test_sql_null_json_null_and_native_jsonb_order(retained_history_engine):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        initial = _applicant_digest(connection)
        connection.execute(sa.text("UPDATE public.applicants SET assessment_profile='null'::jsonb"))
        assert _applicant_digest(connection) != initial
        connection.execute(sa.text('UPDATE public.applicants SET assessment_profile=\'{"a":1,"b":[2,3]}\'::jsonb'))
        ordered = _applicant_digest(connection)
        connection.execute(sa.text('UPDATE public.applicants SET assessment_profile=\'{"b":[2,3],"a":1}\'::jsonb'))
        assert _applicant_digest(connection) == ordered


@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE public.applicants SET assessment_token_hash=md5(gen_random_uuid()::text)",
        "UPDATE public.applicants SET onboarding_token_hash=md5(gen_random_uuid()::text)",
        "UPDATE public.platform_settings SET value=md5(gen_random_uuid()::text)",
        "UPDATE public.applicants SET notes='unchanged-id mutation'",
        "UPDATE public.email_outbox SET tenant_id=(SELECT id FROM public.tenants WHERE id<>email_outbox.tenant_id LIMIT 1)",
        "UPDATE public.onboarding_tasks SET key='changed-composite-member'",
    ),
)
def test_nonkey_sensitive_and_tenant_cells_are_digest_only(retained_history_engine, statement):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        # Only native statement and digest packets, never sensitive result cells.
        before = history._observe_rows(connection)
        assert connection.execute(sa.text(statement)).rowcount == 1
        after = history._observe_rows(connection)
        assert after != before
        assert all(len(digest) == 64 for table in after for _, digest in table.rows)
        assert "value=" not in repr(after) and "assessment_token_hash" not in repr(after)


def test_float_binary_timestamp_infinity_and_timezone(retained_history_engine):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        connection.execute(sa.text("UPDATE public.applicants SET assessment_score='0'::float8"))
        positive_zero = _applicant_digest(connection)
        connection.execute(sa.text("UPDATE public.applicants SET assessment_score='-0'::float8"))
        assert _applicant_digest(connection) != positive_zero
        connection.execute(sa.text("UPDATE public.applicants SET assessment_score='1.0000000000000002'::float8"))
        adjacent = _applicant_digest(connection)
        connection.execute(sa.text("UPDATE public.applicants SET assessment_score='1'::float8"))
        assert _applicant_digest(connection) != adjacent
        connection.execute(sa.text("UPDATE public.applicants SET assessment_taken_at='infinity'::timestamptz"))
        infinity = _applicant_digest(connection)
        connection.execute(sa.text("UPDATE public.applicants SET assessment_taken_at='-infinity'::timestamptz"))
        assert _applicant_digest(connection) != infinity
        connection.execute(sa.text("UPDATE public.applicants SET assessment_taken_at='2026-10-18 12:34:56.123456+00'"))
        finite = _applicant_digest(connection)
        connection.execute(sa.text("SET LOCAL TIME ZONE 'Pacific/Auckland'"))
        assert _applicant_digest(connection) == finite
        connection.execute(
            sa.text("UPDATE public.applicants SET assessment_taken_at=assessment_taken_at+interval '1 microsecond'")
        )
        assert _applicant_digest(connection) != finite


@pytest.mark.parametrize(
    "statement",
    (
        "INSERT INTO public.platform_settings(key,value) VALUES('digest-second',NULL)",
        "DELETE FROM public.platform_settings WHERE key='digest-canary'",
        "UPDATE public.platform_settings SET key='digest-key-changed' WHERE key='digest-canary'",
        "UPDATE public.tenant_entrance_defaults SET tenant_id=(SELECT id FROM public.tenants "
        "WHERE id<>tenant_entrance_defaults.tenant_id LIMIT 1)",
    ),
)
def test_insert_delete_and_real_primary_key_changes(retained_history_engine, statement):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        before = history._observe_rows(connection)
        connection.execute(sa.text(statement))
        assert history._observe_rows(connection) != before


def test_fixed_source_oid_and_composite_key_drift_refused(retained_history_engine):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        before = history._observe_rows(connection)
        connection.execute(sa.text("ALTER TABLE public.platform_settings RENAME TO retained_displaced"))
        with pytest.raises(retained.RetainedSchemaRefused):
            history._observe_rows(connection)
        assert before  # no recovery or fabricated fragment from the failed observation
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        connection.execute(
            sa.text("ALTER TABLE public.onboarding_tasks DROP CONSTRAINT uq_onboarding_tasks_applicant_key")
        )
        with pytest.raises(retained.RetainedSchemaRefused):
            history._observe_rows(connection)


def test_missing_locks_and_no_namespace_override(retained_history_engine):
    with entry_transaction(retained_history_engine) as connection:
        with pytest.raises(history.RetainedHistoryRefused):
            history._observe_rows(connection)
        with pytest.raises(history.RetainedHistoryRefused):
            history._row_query("academy_identity_compat.applicants")
        with pytest.raises(history.RetainedHistoryRefused):
            history._row_query("applicants;SELECT value FROM public.platform_settings")


def test_sensitive_payload_stays_server_side_by_server_comparison(retained_history_engine):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        connection.execute(sa.text("UPDATE public.platform_settings SET value=md5(gen_random_uuid()::text)"))
        connection.execute(sa.text("UPDATE public.applicants SET assessment_token_hash=md5(gen_random_uuid()::text)"))
        before = history._observe_rows(connection)
        assert all(len(row) == 2 for table in before for row in table.rows)
        # Compare the native SHA256 solely on server to each observed digest;
        # even the verification result is boolean, never the underlying secret.
        for table in before:
            query = history._row_query(table.name)
            for key, digest in table.rows:
                assert (
                    connection.scalar(
                        sa.text(f"SELECT EXISTS(SELECT 1 FROM ({query}) q(k,d) WHERE k=:k AND d=:d)"),  # noqa: S608 -- fixed private query
                        {"k": key, "d": digest},
                    )
                    is True
                )


@pytest.fixture
def history_hosted_owner(hosted_declaration, tmp_path):
    with replayed_owner(hosted_declaration, "history", tmp_path) as owner:
        yield owner


def test_genuine_hosted_capture_and_historical_recheck(history_hosted_owner):
    with qualified_root(history_hosted_owner) as (connection, root, context, bindings):
        _populate_retained(connection)
        before_info = dict(connection.info)
        before = history._observe_rows(connection)
        fragment = history._capture_retained_rows(connection, bindings, _hosted_context=context)
        assert type(fragment) is history._RetainedFragment
        assert fragment.connection is connection and fragment.root is root
        assert fragment.physical_xid == connection.scalar(sa.text("SELECT pg_catalog.txid_current()::text"))
        assert fragment.tables == before == history._read_fixed_rows(connection)
        assert fragment.catalog == tuple(sorted(retained._observe_historical_catalog(connection).items()))
        assert history._recheck_retained_rows(connection, fragment, bindings, _hosted_context=context) is None
        assert dict(connection.info) == before_info
        assert connection.get_transaction() is root and root.is_active
        assert "value=" not in repr(fragment) and "assessment_token_hash" not in repr(fragment)
        assert not hasattr(fragment, "verified")


def test_missing_context_capture_fails_closed_and_poison_is_sticky(history_hosted_owner):
    with qualified_root(history_hosted_owner) as (connection, root, context, bindings):
        _populate_retained(connection)
        assert retained._verify_historical_retained_schema(connection) is None
        with pytest.raises(environment.RetainedEnvironmentUnsupported):
            history._capture_retained_rows(connection, bindings)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            history._capture_retained_rows(connection, bindings, _hosted_context=context)
        assert connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize("kind", ("object", "unregistered", "packet"))
def test_forged_context_capture_refuses_and_cannot_repair(history_hosted_owner, kind):
    with qualified_root(history_hosted_owner) as (connection, root, context, bindings):
        _populate_retained(connection)
        fake = {
            "object": object(),
            "unregistered": object.__new__(type(context)),
            "packet": {"verified": True},
        }[kind]
        with pytest.raises(environment.RetainedEnvironmentRefused):
            history._capture_retained_rows(connection, bindings, _hosted_context=fake)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            history._capture_retained_rows(connection, bindings, _hosted_context=context)
        assert connection.get_transaction() is root and root.is_active


def test_wrong_resource_context_capture_refuses(history_hosted_owner, hosted_declaration, tmp_path):
    with replayed_owner(hosted_declaration, "environment", tmp_path) as other_owner:
        with qualified_root(history_hosted_owner) as (connection, root, context, bindings):
            _populate_retained(connection)
            with qualified_root(other_owner) as (other, _other_root, _other_context, _other_bindings):
                _populate_retained(other)
                with pytest.raises(environment.RetainedEnvironmentRefused):
                    history._capture_retained_rows(other, bindings, _hosted_context=context)
            with pytest.raises(environment.RetainedEnvironmentRefused):
                history._capture_retained_rows(connection, bindings, _hosted_context=context)
            assert connection.get_transaction() is root and root.is_active


def test_historical_recheck_detects_native_row_drift(history_hosted_owner):
    with qualified_root(history_hosted_owner) as (connection, root, context, bindings):
        _populate_retained(connection)
        fragment = history._capture_retained_rows(connection, bindings, _hosted_context=context)
        connection.execute(sa.text("UPDATE public.platform_settings SET value=md5(gen_random_uuid()::text)"))
        assert history._read_fixed_rows(connection) != fragment.tables
        with pytest.raises(history.RetainedHistoryRefused):
            history._recheck_retained_rows(connection, fragment, bindings, _hosted_context=context)
        assert connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize("role", ["outbox_dispatcher", "platform_outbox_dispatcher"])
def test_historical_capture_still_refuses_premature_successor_public_grants(retained_history_engine, role):
    with entry_transaction(retained_history_engine) as connection:
        _populate_retained(connection)
        retained._verify_historical_retained_schema(connection)
        before = history._public_schema_envelope(connection)
        assert len(before.acl) == 7
        # Only fixed parametrized role literals; never an arbitrary identifier.
        connection.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        after = history._public_schema_envelope(connection)
        assert after.oid == before.oid and after.owner_oid == before.owner_oid
        assert after.raw_acl != before.raw_acl and len(after.acl) == 8
        with pytest.raises(retained.RetainedSchemaRefused):
            retained._verify_historical_retained_schema(connection)
