"""Real hosted resource/authentication canaries, AUTHORED NOT RUN.

No registry patches, injected verification, mocked Docker/SQL, skips, TestClient,
app_user admission, synthetic source packets, or credential-bearing artifacts.
Root alone selects/pins image/platform and runs these on approved hosted CI.
"""

import copy
import os
import pickle
from dataclasses import replace

import psycopg
import pytest
import sqlalchemy as sa

from app.maintenance import retained_environment as environment
from app.maintenance import retained_hosted_genesis as hosted
from app.maintenance import retained_schema as retained
from tests.fixtures.hosted_genesis import (
    declared_settings,
    hosted_declaration,
    hosted_owner,
    qualified_root,
    replayed_owner,
)

# Explicit fixture imports keep this narrow hosted module self-contained.
__all__ = ["hosted_declaration", "hosted_owner"]


def observe(connection, bindings, context):
    return environment.observe_retained_environment(connection, bindings, _hosted_context=context)


def test_real_factory_frozen62_positive_preserves_catalog_root_and_xid(hosted_owner):
    with qualified_root(hosted_owner) as (connection, root, context, bindings):
        before = retained._observe_historical_catalog(connection)
        xid = connection.scalar(sa.text("SELECT pg_catalog.pg_current_xact_id()::text"))
        retained._verify_historical_retained_schema(connection)
        assert observe(connection, bindings, context) is None
        assert connection.get_transaction() is root and root.is_active
        assert connection.scalar(sa.text("SELECT pg_catalog.pg_current_xact_id()::text")) == xid
        assert retained._observe_historical_catalog(connection) == before
        assert not hasattr(hosted_owner, "release")
        assert not hasattr(context, "verified") and not hasattr(context, "__dict__")
        with pytest.raises(TypeError):
            pickle.dumps(context)
        with pytest.raises(TypeError):
            copy.copy(context)


@pytest.mark.parametrize("purpose", ("environment", "history", "assembly"))
def test_separate_predeclared_purpose_replays(hosted_declaration, tmp_path, purpose):
    with replayed_owner(hosted_declaration, purpose, tmp_path) as owner:
        with qualified_root(owner) as (connection, _root, context, bindings):
            assert bindings.target_database == dict(dict(hosted_declaration.purposes)[purpose])["target_database"]
            assert observe(connection, bindings, context) is None


@pytest.mark.parametrize("kind", ("object", "exact_unregistered", "missing", "copied_packet"))
def test_forged_context_refusal_poison_is_sticky(hosted_owner, kind):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        fake = {
            "object": object(),
            "exact_unregistered": object.__new__(type(context)),
            "missing": None,
            "copied_packet": {"verified": True, "service_image": bindings.service_image},
        }[kind]
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, fake)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


@pytest.mark.parametrize("purpose", ("history", "assembly"))
def test_exchanged_declaration_refused_without_sql_retarget(hosted_owner, hosted_declaration, purpose):
    wrong = environment.HostedEnvironmentBindings(**dict(dict(hosted_declaration.purposes)[purpose]))
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, wrong, context)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_substituted_connection_from_same_resource_refused(hosted_owner):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        # This actual independent owner connection is still the wrong object.
        with hosted_owner._connect(hosted_owner.engine) as other:
            with other.begin():
                other.exec_driver_sql("SET LOCAL ROLE app_admin")
                with pytest.raises(environment.RetainedEnvironmentRefused):
                    observe(other, bindings, context)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_actual_wrong_resource_and_database_refused(hosted_owner, hosted_declaration, tmp_path):
    with replayed_owner(hosted_declaration, "history", tmp_path) as other_owner:
        with qualified_root(hosted_owner) as (connection, _root, context, bindings):
            with qualified_root(other_owner) as (other, _other_root, _other_context, _bindings):
                with pytest.raises(environment.RetainedEnvironmentRefused):
                    observe(other, bindings, context)
            with pytest.raises(environment.RetainedEnvironmentRefused):
                observe(connection, bindings, context)


@pytest.mark.parametrize("drift", ("replace_root", "physical_commit_restart", "nested_repaired", "invalidate"))
def test_real_root_and_physical_xid_continuity_refused(hosted_owner, drift):
    with qualified_root(hosted_owner) as (connection, root, context, bindings):
        if drift == "replace_root":
            root.rollback()
            connection.begin()
        elif drift == "physical_commit_restart":
            connection.exec_driver_sql("COMMIT")
            connection.exec_driver_sql("BEGIN")
        elif drift == "nested_repaired":
            connection.begin_nested().rollback()
        else:
            root.rollback()
            connection.invalidate()
            connection.begin()
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


@pytest.mark.parametrize("drift", ("directory_permissions", "hba_repaired", "secret_permissions"))
def test_repaired_control_drift_cannot_revive(hosted_owner, drift):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        if drift == "directory_permissions":
            hosted_owner.home.chmod(0o755)
            hosted_owner.home.chmod(0o700)
        elif drift == "hba_repaired":
            original = hosted_owner.hba.read_bytes()
            hosted_owner.hba.write_bytes(b"local all all trust\n")
            hosted_owner.hba.write_bytes(original)
        else:
            hosted_owner.password.chmod(0o644)
            hosted_owner.password.chmod(0o600)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_actual_extra_short_lived_backend_is_recorded_after_exit(hosted_owner):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        # Real independently opened client bypasses owner registration only for
        # this negative access canary; no factory accepts a caller connection.
        with psycopg.connect(
            host=str(hosted_owner.home / "socket"),
            dbname=bindings.target_database,
            user="postgres",
            password=hosted_owner.secret.decode(),
            connect_timeout=5,
        ):
            pass
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


@pytest.mark.parametrize("role", hosted._RUNTIME)
def test_actual_runtime_authentication_denied_before_decision(hosted_owner, role):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        assert observe(connection, bindings, context) is None
        with pytest.raises(psycopg.OperationalError):
            psycopg.connect(
                host=str(hosted_owner.home / "socket"),
                dbname=bindings.target_database,
                user=role,
                password="unpublished-denial-canary",
                connect_timeout=5,
            )
        # Unexpected access attempt itself poisons the owner's audit continuity.
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_ordinary_commit_never_opens_runtime_authentication(hosted_owner):
    with qualified_root(hosted_owner) as (connection, root, context, bindings):
        assert observe(connection, bindings, context) is None
        root.commit()  # fixture coordinator only; no product final state issued
        with pytest.raises(psycopg.OperationalError):
            psycopg.connect(
                host=str(hosted_owner.home / "socket"),
                dbname=bindings.target_database,
                user="app_user",
                password="unpublished-denial-canary",
                connect_timeout=5,
            )
        connection.begin()
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


@pytest.mark.parametrize(
    "statement",
    (
        "PREPARE TRANSACTION 'academy_canary'",  # max_prepared_transactions=0
        "CREATE PUBLICATION academy_canary FOR ALL TABLES",  # non-superuser app_admin
    ),
)
def test_prepared_and_replication_work_not_available_to_coordinator(hosted_owner, statement):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        with pytest.raises(sa.exc.DBAPIError):
            connection.exec_driver_sql(statement)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_missing_and_mutable_declarations_refuse_before_factory(hosted_declaration):
    values = declared_settings()
    values.pop("history")
    with pytest.raises(hosted.HostedGenesisRefused):
        hosted.declaration_from_settings(values)
    pairs = list(hosted_declaration.purposes)
    wrong = replace(hosted_declaration, purposes=pairs)
    # Pure reconstruction also rejects a coherent-looking mutable container.
    with pytest.raises(hosted.HostedGenesisRefused):
        with hosted.disposable_genesis(wrong, purpose="environment"):
            pytest.fail("mutable declaration must not create resources")


def test_provider_has_no_existing_service_or_dsn_input(hosted_declaration):
    with pytest.raises(TypeError):
        hosted.disposable_genesis(hosted_declaration, purpose="environment", dsn="postgresql://untrusted")
    assert os.environ.get("CI") == "true"


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt))
def test_failure_and_cancellation_destroy_issued_resource_and_storage(hosted_declaration, failure):
    owner = None
    with pytest.raises(failure):
        with hosted.disposable_genesis(hosted_declaration, purpose="environment") as owner:
            raise failure("hosted cleanup canary")
    assert owner is not None and owner.poisoned
    assert not owner.home.exists()
    assert owner.command("ps", "--all", "--quiet", "--filter", "id=" + owner.container).strip() == b""


def test_actual_partial_setup_failure_cleans_new_resource(hosted_declaration):
    values = declared_settings()
    # Valid declaration syntax but PostgreSQL's reserved existing database.
    # This fails AFTER actual container/bootstrap creation, not via a fake.
    values["environment"]["academy_retained_environment_target_database"] = "postgres"
    declaration = hosted.declaration_from_settings(values)
    owner = hosted._Owner(declaration, "environment")
    try:
        with pytest.raises(sa.exc.DBAPIError):
            owner.setup()
    finally:
        owner.close()
    assert owner.poisoned and not owner.home.exists()
    assert owner.command("ps", "--all", "--quiet", "--filter", "name=^/" + owner.name + "$").strip() == b""


def test_actual_storage_cleanup_error_remains_visible(hosted_declaration):
    import shutil

    owner = hosted._Owner(hosted_declaration, "environment")
    try:
        owner.setup()
        blocked = owner.home / "cleanup-canary"
        blocked.mkdir(mode=0o700)
        (blocked / "child").write_text("canary", encoding="ascii")
        blocked.chmod(0)
        with pytest.raises(hosted.HostedGenesisRefused, match="cleanup failed"):
            owner.close()
        assert owner.poisoned
        assert owner.command("ps", "--all", "--quiet", "--filter", "id=" + owner.container).strip() == b""
    finally:
        # The canary restores only its own deliberately obstructed storage.
        if owner.home is not None and owner.home.exists():
            blocked = owner.home / "cleanup-canary"
            if blocked.exists():
                blocked.chmod(0o700)
            shutil.rmtree(owner.home)


def test_stale_context_cannot_outlive_destroyed_resource(hosted_declaration, tmp_path):
    with replayed_owner(hosted_declaration, "environment", tmp_path) as owner:
        with qualified_root(owner) as (connection, _root, context, bindings):
            assert observe(connection, bindings, context) is None
    with pytest.raises(environment.RetainedEnvironmentRefused):
        observe(connection, bindings, context)


def test_real_docker_restart_poison_survives_same_name_and_image(hosted_owner):
    with pytest.raises((hosted.HostedGenesisRefused, sa.exc.DBAPIError)):
        with qualified_root(hosted_owner) as (connection, _root, context, bindings):
            hosted_owner.command("restart", hosted_owner.container)
            with pytest.raises(environment.RetainedEnvironmentRefused):
                observe(connection, bindings, context)
            assert hosted_owner.poisoned
            # Fixture rollback can also refuse because its backend was killed.


def test_actual_persistent_configuration_repair_poison(hosted_owner):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        # Repaired ALTER SYSTEM is still kernel-observed access/config drift.
        hosted_owner.control.exec_driver_sql("ALTER SYSTEM SET log_connections = off")
        hosted_owner.control.exec_driver_sql("ALTER SYSTEM RESET log_connections")
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_same_name_substitution_and_repair_cannot_change_owner_identity(hosted_owner):
    replacement = None
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        hosted_owner.command("rename", hosted_owner.container, hosted_owner.name + "-original")
        try:
            replacement = (
                hosted_owner.command(
                    "create",
                    "--name",
                    hosted_owner.name,
                    "--network=none",
                    "--pull=never",
                    "--platform",
                    hosted_owner.declaration.platform,
                    hosted_owner.declaration.image,
                    "postgres",
                    "-c",
                    "listen_addresses=",
                )
                .decode()
                .strip()
            )
            assert replacement != hosted_owner.container
            with pytest.raises(environment.RetainedEnvironmentRefused):
                observe(connection, bindings, context)
        finally:
            if replacement is not None:
                hosted_owner.command("rm", "--force", "--volumes", replacement)
            hosted_owner.command("rename", hosted_owner.container, hosted_owner.name)
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_actual_socket_unlink_replacement_is_refused(hosted_owner):
    import socket

    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        path = hosted_owner.home / "socket/.s.PGSQL.5432"
        path.unlink()
        replacement = socket.socket(socket.AF_UNIX)
        try:
            replacement.bind(str(path))
            path.chmod(0o700)
            with pytest.raises(environment.RetainedEnvironmentRefused):
                observe(connection, bindings, context)
        finally:
            replacement.close()
            path.unlink()


def test_predecision_no_password_authentication_is_really_denied(hosted_owner):
    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        assert observe(connection, bindings, context) is None
        # passfile/service/PGPASSWORD cannot accidentally satisfy this canary:
        # a wrong explicit password must exercise local SCRAM authentication.
        with pytest.raises(psycopg.OperationalError):
            psycopg.connect(
                host=str(hosted_owner.home / "socket"),
                dbname=bindings.target_database,
                user="postgres",
                password="deliberately-wrong-canary",
                connect_timeout=5,
            )
        with pytest.raises(environment.RetainedEnvironmentRefused):
            observe(connection, bindings, context)


def test_actual_network_none_cannot_open_without_refusal(hosted_owner):
    import subprocess

    with qualified_root(hosted_owner) as (connection, _root, context, bindings):
        try:
            hosted_owner.command("network", "connect", "bridge", hosted_owner.container)
        except subprocess.CalledProcessError:
            # Docker itself enforces none's exclusive network mode. No skipped
            # assertion: actual identity and PostgreSQL gate must still pass.
            assert set(hosted_owner.inspect()[14]) == {"none"}
            assert observe(connection, bindings, context) is None
        else:
            try:
                with pytest.raises(environment.RetainedEnvironmentRefused):
                    observe(connection, bindings, context)
            finally:
                hosted_owner.command("network", "disconnect", "bridge", hosted_owner.container)
            with pytest.raises(environment.RetainedEnvironmentRefused):
                observe(connection, bindings, context)


def test_real_initial_none_network_event_preserves_action_identity_and_time(hosted_owner):
    # Inspect only the actual factory's Docker event baseline. No injected
    # packet or fabricated connect record may make the positive canary pass.
    container_events, network_events = hosted_owner.events
    assert tuple(line.split()[0] for line in container_events) == (b"create", b"start")
    assert len(network_events) == 1, "Pinned hosted Docker must emit its actual initial none connect"
    action, network_id, container_id, timestamp = network_events[0].split()
    assert action == b"connect"
    assert network_id == hosted_owner.identity[14]["none"]["NetworkID"].encode("ascii")
    assert container_id == hosted_owner.container.encode("ascii")
    assert timestamp.isdigit() and int(timestamp) > 0
    assert hosted_owner._events() == hosted_owner.events
    with qualified_root(hosted_owner) as (connection, root, context, bindings):
        assert observe(connection, bindings, context) is None
        assert connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize("interruption", ("cancelled", "keyboard_interrupt", "system_exit"))
def test_control_verification_interruption_propagates_and_poison_is_sticky(hosted_declaration, tmp_path, interruption):
    # Hosted negative fault injection only: no substitute SQL or verification.
    import asyncio

    error = {
        "cancelled": asyncio.CancelledError("hosted verification interrupted"),
        "keyboard_interrupt": KeyboardInterrupt("hosted verification interrupted"),
        "system_exit": SystemExit("hosted verification interrupted"),
    }[interruption]
    with replayed_owner(hosted_declaration, "environment", tmp_path) as owner:
        with qualified_root(owner) as (connection, root, context, bindings):
            assert observe(connection, bindings, context) is None
            assert not owner.poisoned
            reached = []

            def interrupt_control_verification(actual_connection, _cursor, statement, parameters, _context, _many):
                if statement.startswith(
                    "SELECT datname,application_name,backend_xid::text FROM pg_catalog.pg_stat_activity WHERE pid="
                ):
                    assert actual_connection is owner.control
                    assert parameters["pid"] == owner.backend
                    reached.append(statement)
                    raise error

            sa.event.listen(owner.control_engine, "before_cursor_execute", interrupt_control_verification)
            try:
                # The public environment path traverses both nested handlers.
                with pytest.raises(type(error)) as caught:
                    observe(connection, bindings, context)
                assert caught.value is error
                assert len(reached) == 1
                assert owner.poisoned
                assert connection.get_transaction() is root and root.is_active
            finally:
                sa.event.remove(owner.control_engine, "before_cursor_execute", interrupt_control_verification)
            # Removing the interruption cannot repair the poisoned authority.
            with pytest.raises(environment.RetainedEnvironmentRefused):
                observe(connection, bindings, context)
            assert owner.poisoned
            assert connection.get_transaction() is root and root.is_active
        # Only the fixture coordinator ends the caller-owned root.
        assert not root.is_active
        assert owner.poisoned
