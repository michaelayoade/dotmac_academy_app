"""Hosted genuine frozen62 environment canaries; AUTHORED, NOT RUN.

CI must explicitly bind non-secret expectations before any observation. This
slice does not add CI wiring and never skips an absent binding or blesses a
catalog-derived expectation. All planted authority changes roll back.
"""

import hashlib
import json
import os
from dataclasses import replace

import pytest
import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.engine import make_url

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import retained_environment as environment
from app.maintenance import retained_schema as retained
from tests.fixtures.kernel_identity_entry.rehearsal import FIXTURE, LEGACY_HEAD, config_for, verify_legacy_source
from tests.test_kernel_identity_entry import _seed_populated_legacy, entry_transaction


@pytest.fixture(scope="module")
def profile_engine(tmp_path_factory):
    """Own a NEW dedicated empty profile database; never reuse retained_engine.

    Next root-owned CI slice must provision this separately. A module-scoped
    import of retained_engine would initialize its same database twice during
    full collection. No populated fallback, environment mutation or skip.
    """
    assert os.environ.get("CI") == "true", "environment profile rehearsals are hosted CI only"
    url = os.environ.get("RETAINED_ENVIRONMENT_DATABASE_URL")
    assert url, "CI must separately provision RETAINED_ENVIRONMENT_DATABASE_URL"
    target = make_url(url)
    assert target.get_backend_name() == "postgresql" and target.database
    for name in (
        "RETAINED_SCHEMA_DATABASE_URL",
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
                connection, FIXTURE / "alembic/versions", tmp_path_factory.mktemp("profile-entry-env"), applied
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
def hosted_bindings():
    assert os.environ.get("CI") == "true", "hosted environment rehearsals are CI only"
    declared = os.environ.get("ACADEMY_RETAINED_ENVIRONMENT_BINDINGS")
    assert declared, "next CI slice must declare non-secret expected bindings before observation"
    values = json.loads(declared)
    assert type(values) is dict
    key = "academy_retained_environment_extension_versions"
    assert key in values
    values[key] = tuple(tuple(item) for item in values[key])
    return environment.bindings_from_settings(values)


def test_genuine_frozen62_profile_checks_remain_unsupported(profile_engine, hosted_bindings):
    """Positive uses real frozen62, real roles and required prior CI declaration."""
    with entry_transaction(profile_engine) as connection:
        before = environment._observe_hosted_environment(connection)
        environment._check_fixed_environment(before, hosted_bindings)
        root = connection.get_transaction()
        statements = []

        def observe_statement(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(connection, "before_cursor_execute", observe_statement)
        try:
            with pytest.raises(environment.RetainedEnvironmentUnsupported):
                environment.observe_retained_environment(connection, hosted_bindings)
        finally:
            event.remove(connection, "before_cursor_execute", observe_statement)
        assert statements and all(s.lstrip().upper().startswith("SELECT") for s in statements)
        assert connection.get_transaction() is root and root.is_active
        assert environment._observe_hosted_environment(connection) == before
        assert before["role_database_settings"] == ((False,),)
        assert before["memberships"] == ()


@pytest.mark.parametrize(
    "statement",
    (
        "ALTER ROLE app_user NOLOGIN",
        "ALTER ROLE academy_lab_worker INHERIT",
        "ALTER ROLE platform_api BYPASSRLS",
        "ALTER ROLE outbox_dispatcher CREATEDB",
        "ALTER ROLE platform_outbox_dispatcher CREATEROLE",
        "ALTER ROLE app_user REPLICATION",
        "ALTER ROLE app_user SUPERUSER",
        "GRANT app_user TO outbox_dispatcher WITH INHERIT FALSE, SET FALSE, ADMIN FALSE",
        "GRANT app_admin TO platform_api WITH INHERIT FALSE, SET TRUE",
        "ALTER ROLE app_user SET row_security TO off",
        "ALTER ROLE postgres SET row_security TO off",
        "GRANT SET ON PARAMETER session_replication_role TO app_user",
        "GRANT CREATE ON SCHEMA public TO PUBLIC",
        "REVOKE USAGE ON SCHEMA public FROM PUBLIC",
        "ALTER SCHEMA public OWNER TO app_admin",
        "GRANT USAGE ON SCHEMA public TO outbox_dispatcher",
        "ALTER DEFAULT PRIVILEGES FOR ROLE app_admin GRANT SELECT ON TABLES TO app_user",
        "ALTER DEFAULT PRIVILEGES FOR ROLE app_admin IN SCHEMA public GRANT USAGE ON SEQUENCES TO app_user",
        "GRANT SELECT ON public.applicants TO outbox_dispatcher",
        "GRANT INSERT(email) ON public.applicants TO platform_outbox_dispatcher",
        "ALTER TABLE public.applicants OWNER TO platform_api",
        "CREATE SEQUENCE public.environment_planted_sequence OWNED BY NONE",
        "CREATE SCHEMA environment_planted_schema AUTHORIZATION app_user",
        "CREATE FUNCTION public.environment_planted_routine() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
        "ALTER FUNCTION public.app_current_tenant_id() SET row_security TO off",
        "CREATE EXTENSION hstore",
    ),
)
def test_planted_authority_refused(profile_engine, hosted_bindings, statement):
    with entry_transaction(profile_engine) as connection:
        # The physical setup session is postgres; the candidate observes only
        # the app_admin DDL identity. These changes exist solely in rollback.
        connection.execute(sa.text("SET LOCAL ROLE postgres"))
        connection.execute(sa.text(statement))
        if statement.startswith("CREATE SEQUENCE"):
            connection.execute(sa.text("ALTER SEQUENCE public.environment_planted_sequence OWNER TO app_user"))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(environment.RetainedEnvironmentRefused) as failure:
            environment.observe_retained_environment(connection, hosted_bindings)
        assert type(failure.value) is not environment.RetainedEnvironmentUnsupported


@pytest.mark.parametrize(
    "change",
    (
        {"target_database": "wrong_declared_database"},
        {"server_version_num": 160001},
        {"lc_collate": "wrong_declared_locale"},
        {"encoding": "LATIN1"},
        {"setup_session": "app_admin"},
        {"extension_versions": (("plpgsql", "99.9"),)},
    ),
)
def test_environment_binding_contradiction_refused(profile_engine, hosted_bindings, change):
    if "server_version_num" in change:
        change = {"server_version_num": hosted_bindings.server_version_num + 1}
    with entry_transaction(profile_engine) as connection:
        with pytest.raises(environment.RetainedEnvironmentRefused) as failure:
            environment.observe_retained_environment(connection, replace(hosted_bindings, **change))
        assert type(failure.value) is not environment.RetainedEnvironmentUnsupported


@pytest.mark.parametrize("setting", ("row_security=off", "session_replication_role=replica"))
def test_unsafe_session_guc_refused(profile_engine, hosted_bindings, setting):
    with entry_transaction(profile_engine) as connection:
        connection.execute(sa.text("SET LOCAL ROLE postgres"))
        connection.execute(sa.text("SET LOCAL " + setting))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(environment.RetainedEnvironmentRefused) as failure:
            environment.observe_retained_environment(connection, hosted_bindings)
        assert type(failure.value) is not environment.RetainedEnvironmentUnsupported


def test_missing_binding_never_observes(profile_engine):
    with entry_transaction(profile_engine) as connection:
        statements = []

        def observe_statement(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(connection, "before_cursor_execute", observe_statement)
        try:
            with pytest.raises(environment.RetainedEnvironmentUnsupported):
                environment.observe_retained_environment(connection, None)
        finally:
            event.remove(connection, "before_cursor_execute", observe_statement)
        assert statements == []
        with pytest.raises(environment.RetainedEnvironmentUnsupported):
            environment.bindings_from_settings({})


def test_service_image_expectation_cannot_create_authority(profile_engine, hosted_bindings):
    with entry_transaction(profile_engine) as connection:
        # An asserted alternate image cannot be authenticated through SQL and
        # therefore still cannot admit even when database metadata matches.
        candidate = replace(hosted_bindings, service_image="postgres:16-unproven")
        with pytest.raises(environment.RetainedEnvironmentUnsupported):
            environment.observe_retained_environment(connection, candidate)


@pytest.mark.parametrize("change", ("public_create", "runtime_owner", "role_database_setting"))
def test_planted_database_authority_refused(profile_engine, hosted_bindings, change):
    environment._check_bindings(hosted_bindings)
    database = hosted_bindings.target_database
    with entry_transaction(profile_engine) as connection:
        connection.execute(sa.text("SET LOCAL ROLE postgres"))
        if change == "public_create":
            statement = f'GRANT CREATE ON DATABASE "{database}" TO PUBLIC'
        elif change == "runtime_owner":
            statement = f'ALTER DATABASE "{database}" OWNER TO app_user'
        else:
            statement = f'ALTER ROLE app_user IN DATABASE "{database}" SET row_security TO off'
        connection.execute(sa.text(statement))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(environment.RetainedEnvironmentRefused) as failure:
            environment.observe_retained_environment(connection, hosted_bindings)
        assert type(failure.value) is not environment.RetainedEnvironmentUnsupported


def test_capture_unqualified_frozen62_environment_metadata(profile_engine, tmp_path, record_property):
    """Read genuine metadata without bindings; never run fixed-profile checks.

    This last test produces initial hosted evidence for later source review.
    It neither derives expectations from observation nor qualifies a profile.
    Serialization accepts only exact JSON scalar types and nested tuples.
    """
    with entry_transaction(profile_engine) as connection:
        root = connection.get_transaction()
        catalog = environment._observe_hosted_environment(connection)
        assert connection.get_transaction() is root and root.is_active
    expected_keys = {
        "context",
        "database",
        "roles",
        "memberships",
        "role_database_settings",
        "default_acl_overrides",
        "parameter_acl_grants",
        "database_acl",
        "schemas",
        "schema_acl",
        "effective_database",
        "effective_schema",
        "runtime_ownership",
        "outbox_tables",
        "outbox_columns",
        "extensions",
        "additional_routines",
    }
    assert set(catalog) == expected_keys

    def metadata_value(value):
        if value is None or type(value) in (str, int, bool):
            return value
        if type(value) is tuple:
            return [metadata_value(item) for item in value]
        raise TypeError("Unsupported environment metadata scalar type")

    artifact = {
        "kind": "unqualified_frozen62_hosted_environment",
        "schema_version": 1,
        "admission_authority": False,
        "source_only": True,
        "source_profile": {
            "name": environment._PROFILE.name,
            "source_manifest_sha256": environment._PROFILE.source_manifest_sha256,
            "actual_a5_ci_sha256": environment._PROFILE.actual_a5_ci_sha256,
            "actual_role_script_blob": environment._PROFILE.actual_role_script_blob,
        },
        "fixed_profile_checks": "NOT RUN",
        "binding_expectations": "NOT SUPPLIED",
        "catalog": {key: metadata_value(catalog[key]) for key in sorted(expected_keys)},
        "unsupported_gates": [
            "required trusted Settings/CI environment binding adoption pending",
            "fixed profile checks and planted environment canaries unqualified",
            "service image identity authentication pending",
            "exclusive disposable Genesis boundary authentication pending",
            "observation is not admission, production approval, fence or a004 authority",
        ],
    }
    payload = (json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    path = tmp_path / "frozen62-retained-environment-source-only.json"
    path.write_bytes(payload)
    record_property("retained_environment_metadata_path", str(path))
    record_property("retained_environment_metadata_sha256", hashlib.sha256(payload).hexdigest())
