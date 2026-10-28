"""Authored hosted-only coupled canaries; UNEXECUTED in this source capsule.

Requires the genuine installed importer with lossless JSONB + composed-head
support, credential-key revision + audit declaration, and unchanged a5 entry
fixture/tests. No fake installed package or replay witness. This fixture
qualifies synthetic value copy, not live adoption/auth.
"""

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest
import sqlalchemy as sa
from dotmac_kernel import audit_actions, credential_lifecycle, security
from dotmac_kernel.migrations import versions_dir
from dotmac_kernel.migrations.gate import run_gate
from dotmac_kernel.migrations.identity_history import (
    IdentityHistoryCohortV1,
    IdentityHistoryImportOperationV1,
    IdentityHistoryImportRefused,
    IdentityHistoryManifestV1,
    IdentityHistoryRelationsV1,
)
from dotmac_kernel.namespaces import HOST_MIGRATION_OWNERS, NamespaceRegistry
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError
from sqlalchemy.sql.elements import quoted_name

from alembic import command
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.maintenance.identity_history import import_academy_identity_history
from tests.fixtures.kernel_identity_entry.rehearsal import (
    COLLISIONS,
    COMPATIBILITY_SCHEMA,
    config_for,
    installed_kernel,
    plan_entry,
    relocate,
    replay_kernel,
    snapshot,
)
from tests.test_kernel_identity_entry import (
    entry_transaction,
    legacy_engine,
    public_footprint,
)

# Importing the genuine existing fixture is deliberate; not a duplicate DB owner.
assert legacy_engine
ASSEMBLY = Path(__file__).resolve().parents[1] / "alembic/identity_assembly_versions"


def test_reserved_assembly_composition():
    registry = NamespaceRegistry(HOST_MIGRATION_OWNERS)
    report = run_gate((), (Path(versions_dir()), ASSEMBLY), registry=registry, bindings=())
    assert report.violations == ()


def _synthetic_source_setup(connection):
    # Synthetic setup precedes locked copy. Only genuine owner verification
    # authorizes fixture token minting; no real password/session is collected.
    password = "hosted-academy-identity-canary-only"
    material = security.hash_password(password)
    people = connection.execute(sa.text("SELECT id,tenant_id FROM public.people ORDER BY id")).all()
    for person, tenant in people:
        subject = credential_lifecycle.CredentialSubjectRef(
            application="synthetic",
            principal_kind="person",
            principal_ref=str(person),
            credential_ref="synthetic",
        )
        store = Mock()
        store.load.return_value = credential_lifecycle.CredentialSnapshot(
            subject=subject,
            password_hash=material,
            credential_version=0,
            is_active=True,
        )
        owner = credential_lifecycle.CredentialLifecycle(store=store, sessions=Mock(), recovery=Mock(), audit=Mock())
        result = owner.verify(subject, password)
        assert result.verdict == "accepted" and result.replacement_hash is None
        token, expiry = security.issue_access_token(person, tenant)
        connection.execute(
            sa.text("UPDATE public.auth_sessions SET token_hash=:token,expires_at=:expiry WHERE person_id=:person"),
            {"token": security.hash_token(token), "expiry": expiry, "person": person},
        )
    connection.execute(
        sa.text(
            "UPDATE public.user_credentials SET "
            "password_hash=:material,failed_login_attempts=-3,locked_until=now()+interval '1 hour'"
        ),
        {"material": material},
    )
    connection.execute(
        sa.text("UPDATE public.people SET status='suspended',avatar_path='synthetic/avatar',prefs='null'::jsonb")
    )
    connection.execute(sa.text("UPDATE public.audit_events SET details='null'::jsonb"))
    connection.execute(
        sa.text("UPDATE public.user_credentials SET email='Alias@EXAMPLE.invalid' WHERE email='alias@example.invalid'")
    )


@contextmanager
def _prepared(engine, tmp_path, monkeypatch):
    # Actual canonical from_manifests includes its owned declaration in API4;
    # an older installed artifact correctly refuses this test's gate.
    registry = audit_actions.AuditActionRegistry.from_manifests(())
    assert registry.owner("identity.history_imported") == "kernel"
    monkeypatch.setattr(audit_actions, "_active_registry", registry)
    with entry_transaction(engine) as connection:
        _synthetic_source_setup(connection)
        plan = plan_entry(connection)
        relocate(connection, plan)
        kernel = installed_kernel(connection, tmp_path / "inspect")
        assert any(r.revision == "0030_credential_tenant_key" for r in kernel.revisions)
        applied = []
        replay_kernel(connection, tmp_path / "kernel", applied)
        assert tuple(applied) == kernel.revisions
        composed = []
        cfg = config_for(connection, ASSEMBLY, tmp_path / "composed", composed)
        cfg.set_main_option("version_locations", str(versions_dir()) + " " + str(ASSEMBLY))
        command.upgrade(cfg, "a002_credential_reset_state")
        assert [r.revision for r in composed] == [
            "a001_identity_extensions",
            "a002_credential_reset_state",
        ]
        relations = {}
        cohort = {}
        for name in COLLISIONS:
            relations[name] = connection.scalar(
                sa.text("SELECT to_regclass(:relation)::oid"),
                {"relation": COMPATIBILITY_SCHEMA + "." + name},
            )
            # Closed fixture relation allowlist; no credential material fetched.
            source = sa.table(quoted_name(name, True), sa.column("id", sa.Uuid), schema=COMPATIBILITY_SCHEMA)
            cohort[name] = frozenset(connection.scalars(sa.select(source.c.id)))
        expected = IdentityHistoryManifestV1(
            relations=IdentityHistoryRelationsV1(schema=COMPATIBILITY_SCHEMA, **relations),
            cohort=IdentityHistoryCohortV1(**cohort),
            source_revision="a" * 40,
            session_issuance_review_ref="synthetic-owner-verified-population",
            password_session_ids=cohort["auth_sessions"],
            installed_kernel_head=kernel.head,
        )
        operation = IdentityHistoryImportOperationV1(
            is_active=True,
            activated_person_ids=cohort["people"],
            reason="Synthetic copy canary",
            decision_ref="synthetic-hosted-copy",
            actor_type="service",
            actor_id="academy-maintenance-canary",
            source_application="dotmac_academy_app",
        )
        yield connection, expected, operation


def test_same_root_lossless_policy_alias_and_json_null_copy(legacy_engine, tmp_path, monkeypatch):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        root = connection.get_transaction()
        before = snapshot(connection, COMPATIBILITY_SCHEMA)
        receipt = import_academy_identity_history(connection, expected, operation)
        assert connection.get_transaction() is root and root.is_active
        assert receipt.counts.people == len(expected.cohort.people)
        assert snapshot(connection, COMPATIBILITY_SCHEMA) == before
        for statement in (
            "SELECT count(*)=0 FROM academy_identity_compat.people s FULL JOIN "
            "public.academy_account_profiles t ON s.id=t.party_id WHERE s.id IS NULL OR t.party_id"
            " IS NULL OR (s.tenant_id,s.status,s.avatar_path,s.prefs,s.created_at,s.updated_at) IS"
            " DISTINCT FROM (t.tenant_id,t.status,t.avatar_path,t.prefs,t.created_at,t.updated_at)",
            "SELECT count(*)=0 FROM academy_identity_compat.user_credentials s FULL JOIN "
            "public.academy_credential_policies t ON s.id=t.credential_id WHERE s.id IS NULL OR "
            "t.credential_id IS NULL OR "
            "(s.tenant_id,s.email,s.failed_login_attempts,s.locked_until,s.created_at,s.updated_at)"
            " IS DISTINCT FROM "
            "(t.tenant_id,t.email,t.failed_login_attempts,t.locked_until,t.created_at,t.updated_at)",
            "SELECT bool_and(lifecycle_version=0 AND reset_required IS FALSE) FROM public.academy_credential_policies",
            "SELECT count(*)=0 FROM academy_identity_compat.user_credentials s JOIN "
            "public.user_credentials t ON s.id=t.id WHERE s.password_hash IS DISTINCT FROM "
            "t.password_hash",
            "SELECT count(*)=0 FROM academy_identity_compat.auth_sessions s FULL JOIN "
            "public.auth_sessions t ON s.id=t.id WHERE s.id IS NULL OR t.id IS NULL OR "
            "(s.tenant_id,s.person_id,s.token_hash,s.expires_at,s.revoked_at,s.created_at,s.updated_at)"
            " IS DISTINCT FROM "
            "(t.tenant_id,t.party_id,t.token_hash,t.expires_at,t.revoked_at,t.created_at,t.updated_at)"
            " OR t.external_identity_binding_id IS NOT NULL",
            "SELECT bool_and(p.is_active AND a.status='suspended' AND a.prefs='null'::jsonb) FROM "
            "public.parties p JOIN public.academy_account_profiles a ON a.party_id=p.id",
            "SELECT bool_and(t.details='null'::jsonb AND t.occurred_at IS NULL AND t.actor_type IS"
            " NULL) FROM academy_identity_compat.audit_events s JOIN public.audit_events t ON "
            "t.id=s.id",
            "SELECT count(*)=2 FROM (SELECT c.party_id FROM public.academy_credential_policies p "
            "JOIN public.user_credentials c ON c.id=p.credential_id GROUP BY c.party_id HAVING "
            "count(*)=2) aliases",
        ):
            # Boolean-only checks avoid rendering sensitive rows on assertion.
            assert connection.scalar(sa.text(statement)) is True


@pytest.mark.parametrize(
    "json_value",
    [
        "null",
        "[]",
        '[1,"value",null]',
        "true",
        "7",
        '"value"',
        "{}",
        "0.12345678901234567890123456789",
        '{"nested":[0.12345678901234567890123456789,{"large":1e1000}]}',
        "1e1000",
        "9" * 1000,
        "9" * 5000,
    ],
    ids=[
        "json_null",
        "empty_array",
        "mixed_array",
        "boolean",
        "integer",
        "string",
        "object",
        "high_precision_decimal",
        "nested_precision",
        "large_exponent",
        "thousand_digit_integer",
        "five_thousand_digit_integer",
    ],
)
def test_arbitrary_jsonb_details_and_prefs_are_not_object_coerced(
    legacy_engine,
    tmp_path,
    monkeypatch,
    json_value,
):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        # Synthetic fixture mutation precedes importer locks/read; runtime
        # decoder/coordinator never writes a source relation.
        for table, column in (("people", "prefs"), ("audit_events", "details")):
            source = sa.table(
                quoted_name(table, True),
                sa.column(quoted_name(column, True), JSONB),
                schema=COMPATIBILITY_SCHEMA,
            )
            connection.execute(
                sa.update(source).values({column: sa.cast(sa.bindparam("value", type_=sa.Text), JSONB)}),
                {"value": json_value},
            )
        import_academy_identity_history(connection, expected, operation)
        assert (
            connection.scalar(
                sa.text(
                    "SELECT bool_and(t.prefs IS NOT DISTINCT FROM s.prefs) FROM "
                    "academy_identity_compat.people s JOIN public.academy_account_profiles t ON "
                    "t.party_id=s.id"
                )
            )
            is True
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT bool_and(t.details IS NOT DISTINCT FROM s.details) FROM "
                    "academy_identity_compat.audit_events s JOIN public.audit_events t ON t.id=s.id"
                )
            )
            is True
        )


@pytest.mark.parametrize(
    "table,key",
    [
        ("academy_account_profiles", "party_id"),
        ("academy_credential_policies", "credential_id"),
    ],
)
def test_extension_tenant_rls_and_cross_tenant_fk(legacy_engine, tmp_path, monkeypatch, table, key):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        import_academy_identity_history(connection, expected, operation)
        tenants = sorted(expected.cohort.tenants, key=str)
        target_table = sa.table(quoted_name(table, True), sa.column("tenant_id", sa.Uuid), schema="public")
        for role in ("app_user", "platform_api"):
            connection.execute(sa.text(f"SET LOCAL ROLE {role}"))
            connection.execute(
                sa.text("SELECT set_config('app.current_tenant',:tenant,true)"),
                {"tenant": str(tenants[0])},
            )
            assert set(connection.scalars(sa.select(target_table.c.tenant_id))) == {tenants[0]}
            assert (
                connection.execute(
                    sa.update(target_table)
                    .where(target_table.c.tenant_id == sa.bindparam("other", type_=sa.Uuid))
                    .values(tenant_id=target_table.c.tenant_id),
                    {"other": tenants[1]},
                ).rowcount
                == 0
            )
            connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        # Admin bypasses RLS; the composite FK itself rejects tenant drift.
        with pytest.raises(DBAPIError) as failure:
            with connection.begin_nested():
                connection.execute(
                    sa.update(target_table)
                    .where(target_table.c.tenant_id == sa.bindparam("tenant", type_=sa.Uuid))
                    .values(tenant_id=sa.bindparam("other", type_=sa.Uuid)),
                    {"other": tenants[1], "tenant": tenants[0]},
                )
        assert failure.value.orig.sqlstate == "23503"


def test_account_requires_person_subtype(legacy_engine, tmp_path, monkeypatch):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        import_academy_identity_history(connection, expected, operation)
        tenant = next(iter(expected.cohort.tenants))
        with pytest.raises(DBAPIError) as failure:
            with connection.begin_nested():
                party = connection.scalar(
                    sa.text(
                        "INSERT INTO public.parties(id,tenant_id,party_type,display_name,email) "
                        "VALUES(gen_random_uuid(),:tenant,'organization','Synthetic',NULL) RETURNING id"
                    ),
                    {"tenant": tenant},
                )
                connection.execute(
                    sa.text(
                        "INSERT INTO "
                        "public.academy_account_profiles(party_id,tenant_id,status,prefs,created_at,updated_at)"
                        " VALUES(:party,:tenant,'active','{}'::jsonb,now(),now())"
                    ),
                    {"party": party, "tenant": tenant},
                )
        assert failure.value.orig.sqlstate == "23503"


def test_missing_real_credential_key_refuses_before_extension_ddl(legacy_engine, tmp_path):
    with entry_transaction(legacy_engine) as connection:
        relocate(connection, plan_entry(connection))
        applied = []
        replay_kernel(connection, tmp_path / "kernel", applied)
        connection.execute(
            sa.text("ALTER TABLE public.user_credentials DROP CONSTRAINT uq_user_credentials_tenant_id_id")
        )
        cfg = config_for(connection, ASSEMBLY, tmp_path / "assembly", [])
        cfg.set_main_option("version_locations", str(versions_dir()) + " " + str(ASSEMBLY))
        revision = ScriptDirectory.from_config(cfg).get_revision("a001_identity_extensions")
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(ValueError, match="credential tenant key"):
                revision.module.upgrade()
        assert connection.scalar(sa.text("SELECT to_regclass('public.academy_account_profiles') IS NULL"))


def test_occupied_extension_refuses_before_canonical_call(legacy_engine, tmp_path, monkeypatch):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        import_academy_identity_history(connection, expected, operation)
        # Keep one extension row occupied; do not pretend a second import works.
        calls = []
        monkeypatch.setattr(
            "app.maintenance.identity_history.import_identity_history",
            lambda *args, **kwargs: calls.append(True),
        )
        with pytest.raises(IdentityHistoryImportRefused):
            import_academy_identity_history(connection, expected, operation)
        assert calls == []


@pytest.mark.parametrize(
    "table,assignment",
    [
        ("academy_account_profiles", "NEW.status := 'rewritten';"),
        ("academy_credential_policies", "NEW.email := 'rewritten@example.invalid';"),
    ],
)
@pytest.mark.parametrize("enable", ["ENABLE", "ENABLE REPLICA", "ENABLE ALWAYS"])
def test_enabled_product_trigger_refuses_before_canonical_copy(
    legacy_engine,
    tmp_path,
    monkeypatch,
    table,
    assignment,
    enable,
):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        # Closed synthetic constants; a BEFORE INSERT rewrite is a sensitivity
        # control proving ordinary catalog/column/FK checks are insufficient.
        connection.execute(
            sa.text(
                "CREATE FUNCTION public.academy_rewrite_canary() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN " + assignment + " RETURN NEW; END; $$"
            )
        )
        connection.execute(
            sa.text(
                f"CREATE TRIGGER academy_rewrite_canary BEFORE INSERT ON public.{table} "
                "FOR EACH ROW EXECUTE FUNCTION public.academy_rewrite_canary()"
            )
        )
        connection.execute(sa.text(f"ALTER TABLE public.{table} {enable} TRIGGER academy_rewrite_canary"))
        source = snapshot(connection, COMPATIBILITY_SCHEMA)
        footprint = public_footprint(connection)
        import app.maintenance.identity_history as academy_history

        real_import = academy_history.import_identity_history
        calls = []

        def observed_import(*args, **kwargs):
            calls.append(True)
            return real_import(*args, **kwargs)

        monkeypatch.setattr(academy_history, "import_identity_history", observed_import)
        with pytest.raises(IdentityHistoryImportRefused):
            import_academy_identity_history(connection, expected, operation)
        assert calls == []
        assert snapshot(connection, COMPATIBILITY_SCHEMA) == source
        assert public_footprint(connection) == footprint
        for target in (
            "tenants",
            "tenant_domains",
            "parties",
            "party_persons",
            "user_credentials",
            "auth_sessions",
            "roles",
            "party_role_grants",
            "audit_events",
            "academy_account_profiles",
            "academy_credential_policies",
        ):
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(sa.table(quoted_name(target, True), schema="public"))
                )
                == 0
            )


@pytest.mark.parametrize("table", ["academy_account_profiles", "academy_credential_policies"])
@pytest.mark.parametrize("enable", ["ENABLE", "ENABLE REPLICA", "ENABLE ALWAYS"])
def test_enabled_product_rule_refuses_before_canonical_copy(
    legacy_engine,
    tmp_path,
    monkeypatch,
    table,
    enable,
):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        # Closed synthetic constants: this rule silently discards INSERT rows
        # while leaving the accepted column/FK/trigger/RLS/ACL catalog intact.
        connection.execute(
            sa.text(f"CREATE RULE academy_discard_canary AS ON INSERT TO public.{table} DO INSTEAD NOTHING")
        )
        connection.execute(sa.text(f"ALTER TABLE public.{table} {enable} RULE academy_discard_canary"))
        source = snapshot(connection, COMPATIBILITY_SCHEMA)
        footprint = public_footprint(connection)
        rules_before = tuple(
            connection.execute(
                sa.text(
                    "SELECT oid,ev_class,ev_enabled FROM pg_rewrite WHERE ev_class=to_regclass(:table) ORDER BY oid"
                ),
                {"table": "public." + table},
            ).tuples()
        )
        import app.maintenance.identity_history as academy_history

        real_import = academy_history.import_identity_history
        calls = []

        def observed_import(*args, **kwargs):
            calls.append(True)
            return real_import(*args, **kwargs)

        monkeypatch.setattr(academy_history, "import_identity_history", observed_import)
        with pytest.raises(IdentityHistoryImportRefused):
            import_academy_identity_history(connection, expected, operation)
        assert calls == []
        assert snapshot(connection, COMPATIBILITY_SCHEMA) == source
        assert public_footprint(connection) == footprint
        assert (
            tuple(
                connection.execute(
                    sa.text(
                        "SELECT oid,ev_class,ev_enabled FROM pg_rewrite WHERE ev_class=to_regclass(:table) ORDER BY oid"
                    ),
                    {"table": "public." + table},
                ).tuples()
            )
            == rules_before
        )
        for target in (
            "tenants",
            "tenant_domains",
            "parties",
            "party_persons",
            "user_credentials",
            "auth_sessions",
            "roles",
            "party_role_grants",
            "audit_events",
            "academy_account_profiles",
            "academy_credential_policies",
        ):
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(sa.table(quoted_name(target, True), schema="public"))
                )
                == 0
            )


@pytest.mark.parametrize(
    "drift",
    [
        "missing_column",
        "defaulted",
        "wrong_width",
        "nullable",
        "identity",
        "generated",
        "missing_check",
        "wrong_name",
        "wrong_column",
        "negative_allowed",
        "unvalidated",
        "extra_check",
    ],
)
def test_lifecycle_version_schema_drift_refuses_before_canonical_copy(
    legacy_engine,
    tmp_path,
    monkeypatch,
    drift,
):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        table = "public.academy_credential_policies"
        check = "ck_academy_policy_lifecycle_version"
        if drift == "missing_column":
            connection.execute(sa.text(f"ALTER TABLE {table} DROP COLUMN lifecycle_version"))
        elif drift == "defaulted":
            connection.execute(sa.text(f"ALTER TABLE {table} ALTER COLUMN lifecycle_version SET DEFAULT 0"))
        elif drift == "wrong_width":
            connection.execute(sa.text(f"ALTER TABLE {table} ALTER COLUMN lifecycle_version TYPE INTEGER"))
        elif drift == "nullable":
            connection.execute(sa.text(f"ALTER TABLE {table} ALTER COLUMN lifecycle_version DROP NOT NULL"))
        elif drift == "identity":
            connection.execute(
                sa.text(f"ALTER TABLE {table} ALTER COLUMN lifecycle_version ADD GENERATED ALWAYS AS IDENTITY")
            )
        elif drift == "generated":
            connection.execute(sa.text(f"ALTER TABLE {table} DROP COLUMN lifecycle_version"))
            connection.execute(
                sa.text(
                    f"ALTER TABLE {table} ADD COLUMN lifecycle_version BIGINT "
                    "GENERATED ALWAYS AS (0::bigint) STORED NOT NULL"
                )
            )
            connection.execute(sa.text(f"ALTER TABLE {table} ADD CONSTRAINT {check} CHECK(lifecycle_version >= 0)"))
        elif drift == "wrong_name":
            connection.execute(sa.text(f"ALTER TABLE {table} RENAME CONSTRAINT {check} TO unexpected_version_check"))
        elif drift == "extra_check":
            connection.execute(
                sa.text(
                    f"ALTER TABLE {table} ADD CONSTRAINT unexpected_counter_check CHECK(failed_login_attempts >= 0)"
                )
            )
        else:
            connection.execute(sa.text(f"ALTER TABLE {table} DROP CONSTRAINT {check}"))
            if drift != "missing_check":
                expression = (
                    "failed_login_attempts >= 0"
                    if drift == "wrong_column"
                    else "lifecycle_version >= -1"
                    if drift == "negative_allowed"
                    else "lifecycle_version >= 0"
                )
                suffix = " NOT VALID" if drift == "unvalidated" else ""
                connection.execute(sa.text(f"ALTER TABLE {table} ADD CONSTRAINT {check} CHECK({expression}){suffix}"))
        source = snapshot(connection, COMPATIBILITY_SCHEMA)
        import app.maintenance.identity_history as academy_history

        real_import = academy_history.import_identity_history
        calls = []

        def observed_import(*args, **kwargs):
            calls.append(True)
            return real_import(*args, **kwargs)

        monkeypatch.setattr(academy_history, "import_identity_history", observed_import)
        with pytest.raises(IdentityHistoryImportRefused):
            import_academy_identity_history(connection, expected, operation)
        assert calls == []
        assert snapshot(connection, COMPATIBILITY_SCHEMA) == source
        for target in (
            "tenants",
            "tenant_domains",
            "parties",
            "party_persons",
            "user_credentials",
            "auth_sessions",
            "roles",
            "party_role_grants",
            "audit_events",
            "academy_account_profiles",
            "academy_credential_policies",
        ):
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(sa.table(quoted_name(target, True), schema="public"))
                )
                == 0
            )


def test_persisted_lifecycle_version_bigint_range_and_nonnegative_check(
    legacy_engine,
    tmp_path,
    monkeypatch,
):
    with _prepared(legacy_engine, tmp_path, monkeypatch) as (
        connection,
        expected,
        operation,
    ):
        import_academy_identity_history(connection, expected, operation)
        credential = next(iter(expected.cohort.user_credentials))
        # Stored adoption generation starts explicitly at zero. It is separate
        # from the historical counter, which remains negative in this fixture.
        assert (
            connection.scalar(
                sa.text(
                    "SELECT lifecycle_version=0 AND failed_login_attempts=-3 FROM "
                    "public.academy_credential_policies WHERE credential_id=:credential"
                ),
                {"credential": credential},
            )
            is True
        )
        for value in (2**31, 2**63 - 1):
            connection.execute(
                sa.text(
                    "UPDATE public.academy_credential_policies SET lifecycle_version=:value WHERE "
                    "credential_id=:credential"
                ),
                {"value": value, "credential": credential},
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT lifecycle_version=:value FROM public.academy_credential_policies WHERE "
                        "credential_id=:credential"
                    ),
                    {"value": value, "credential": credential},
                )
                is True
            )
        with pytest.raises(DBAPIError) as failure:
            with connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE public.academy_credential_policies SET lifecycle_version=-1 WHERE "
                        "credential_id=:credential"
                    ),
                    {"credential": credential},
                )
        assert failure.value.orig.sqlstate == "23514"


@pytest.mark.parametrize("stage", ["after_accounts", "after_policies"])
def test_extension_fault_rolls_back_canonical_audit_and_every_policy_row(legacy_engine, tmp_path, monkeypatch, stage):
    with legacy_engine.connect() as connection:
        baseline = snapshot(connection)
        footprint = public_footprint(connection)
    with pytest.raises(IdentityHistoryImportRefused):
        with _prepared(legacy_engine, tmp_path, monkeypatch) as (
            connection,
            expected,
            operation,
        ):
            inserted = 0
            stage_count = len(expected.cohort.people if stage == "after_accounts" else expected.cohort.user_credentials)

            def fault(conn, cursor, statement, parameters, context, executemany):
                nonlocal inserted
                target = "academy_account_profiles" if stage == "after_accounts" else "academy_credential_policies"
                if statement.lstrip().startswith("INSERT INTO public." + target):
                    inserted += 1
                    if inserted == stage_count:
                        raise RuntimeError("synthetic post-stage extension fault")

            sa.event.listen(connection, "after_cursor_execute", fault)
            try:
                import_academy_identity_history(connection, expected, operation)
            finally:
                sa.event.remove(connection, "after_cursor_execute", fault)
    with legacy_engine.connect() as connection:
        assert snapshot(connection) == baseline
        assert public_footprint(connection) == footprint
