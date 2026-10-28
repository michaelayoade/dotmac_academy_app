"""The CI commit wrapper cannot broaden its disposable database target."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

from scripts import ci_bootstrap_composed_db as bootstrap


@pytest.fixture
def declarations():
    revision = "a" * 40
    return {
        "CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": "michaelayoade/dotmac_academy_app",
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": revision,
        "ACADEMY_CI_SOURCE_REVISION": revision,
        "ACADEMY_CI_DATABASE_MARKER": f"academy-ci:123:2:{revision}",
        "MIGRATION_DATABASE_URL": "postgresql+psycopg://app_admin:disposable@localhost:5437/academy",
        "MIGRATION_LOGIN_ROLE": "app_admin", "MIGRATION_EFFECTIVE_ROLE": "app_admin",
    }


@pytest.mark.parametrize(("name", "value"), [
    ("CI", "false"), ("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "macOS"), ("GITHUB_REPOSITORY", "elsewhere/academy"),
    ("GITHUB_RUN_ID", "123; echo unsafe"), ("GITHUB_RUN_ATTEMPT", "0"),
    ("ACADEMY_CI_SOURCE_REVISION", "main"), ("ACADEMY_CI_DATABASE_MARKER", "another-run"),
    ("MIGRATION_LOGIN_ROLE", "postgres"), ("MIGRATION_EFFECTIVE_ROLE", "postgres"),
    ("MIGRATION_DATABASE_URL", ""),
    ("MIGRATION_DATABASE_URL", "postgresql+psycopg://app_admin@production:5437/academy"),
    ("MIGRATION_DATABASE_URL", "postgresql+psycopg://app_admin@localhost:5432/academy"),
    ("MIGRATION_DATABASE_URL", "postgresql+psycopg://postgres@localhost:5437/academy"),
    ("MIGRATION_DATABASE_URL", "postgresql+psycopg://app_admin@localhost:5437/another"),
    ("MIGRATION_DATABASE_URL", "postgresql+psycopg://app_admin@localhost:5437/academy?host=production"),
    ("MIGRATION_DATABASE_URL", "postgresql+psycopg://app_admin@localhost:5437/academy?options=-crole=postgres"),
    ("MIGRATION_DATABASE_URL", "postgresql://app_admin@localhost:5437/academy"),
])
def test_rejects_undeclared_or_redirected_targets_before_engine_creation(monkeypatch, declarations, name, value):
    declarations[name] = value
    factory = MagicMock()
    monkeypatch.setattr(bootstrap, "create_engine", factory)
    with pytest.raises(bootstrap.BootstrapRefused):
        bootstrap.bootstrap(declarations, expected_database="academy", verify_only=False)
    factory.assert_not_called()


def test_expected_database_flag_does_not_enlarge_allowlist(declarations):
    declarations["MIGRATION_DATABASE_URL"] = "postgresql+psycopg://app_admin@localhost:5437/other"
    with pytest.raises(bootstrap.BootstrapRefused):
        bootstrap.declared_target(declarations, "other")


@pytest.fixture
def controlled_database(monkeypatch, declarations):
    monkeypatch.setattr(bootstrap, "_checkout_source_revision", lambda: declarations["ACADEMY_CI_SOURCE_REVISION"])
    connection, root, engine = MagicMock(), MagicMock(), MagicMock()
    root.is_active = True
    connection.get_transaction.return_value = root
    connection.in_nested_transaction.return_value = False
    connection.begin.return_value = root
    connection.execute.return_value.one.return_value = (
        "app_admin", "app_admin", "academy", "app_admin", declarations["ACADEMY_CI_DATABASE_MARKER"],
    )
    connection.execute.return_value.scalar_one.return_value = 0
    engine.connect.return_value.__enter__.return_value = connection
    monkeypatch.setattr(bootstrap, "create_engine", lambda *args, **kwargs: engine)
    owner = ModuleType("app.maintenance.fresh_product")
    receipt = SimpleNamespace(revisions=("a010_facilitator_nominations",), catalog_sha256="b" * 64)
    owner.run_fresh_composed_entry = MagicMock(return_value=receipt)
    owner.verify_fresh_composed_db = MagicMock(return_value=receipt)
    monkeypatch.setitem(sys.modules, owner.__name__, owner)
    return connection, root, engine, owner


def test_synthetic_merge_run_sha_does_not_relabel_checked_out_source(declarations):
    declarations["GITHUB_SHA"] = "c" * 40
    _, marker = bootstrap.declared_target(declarations, "academy")
    assert marker.endswith(declarations["ACADEMY_CI_SOURCE_REVISION"])


def test_actual_checkout_must_match_source_declaration(monkeypatch, declarations):
    monkeypatch.setattr(bootstrap, "_checkout_source_revision", lambda: "c" * 40)
    factory = MagicMock()
    monkeypatch.setattr(bootstrap, "create_engine", factory)
    with pytest.raises(bootstrap.BootstrapRefused):
        bootstrap.bootstrap(declarations, expected_database="academy", verify_only=False)
    factory.assert_not_called()


def test_qualified_bootstrap_is_the_only_committing_path(declarations, controlled_database):
    connection, root, engine, owner = controlled_database
    result = bootstrap.bootstrap(declarations, expected_database="academy", verify_only=False)
    owner.run_fresh_composed_entry.assert_called_once_with(
        connection, decision_ref=declarations["ACADEMY_CI_DATABASE_MARKER"],
    )
    owner.verify_fresh_composed_db.assert_not_called()
    root.commit.assert_called_once()
    engine.dispose.assert_called_once()
    assert result == {"revisions": ("a010_facilitator_nominations",), "catalog_sha256": "b" * 64}


def test_verify_only_is_read_only_and_never_commits(declarations, controlled_database):
    connection, root, _, owner = controlled_database
    bootstrap.bootstrap(declarations, expected_database="academy", verify_only=True)
    connection.exec_driver_sql.assert_called_once_with("SET TRANSACTION READ ONLY")
    owner.verify_fresh_composed_db.assert_called_once_with(connection)
    owner.run_fresh_composed_entry.assert_not_called()
    root.commit.assert_not_called()
    root.rollback.assert_called()


@pytest.mark.parametrize("failure", ["wrong_owner", "wrong_marker", "populated", "owner_refusal", "root_drift"])
def test_failed_target_or_qualification_never_commits(declarations, controlled_database, failure):
    connection, root, _, owner = controlled_database
    if failure in ("wrong_owner", "wrong_marker"):
        row = list(connection.execute.return_value.one.return_value)
        row[3 if failure == "wrong_owner" else 4] = "wrong"
        connection.execute.return_value.one.return_value = tuple(row)
    elif failure == "populated":
        connection.execute.return_value.scalar_one.return_value = 1
    elif failure == "owner_refusal":
        owner.run_fresh_composed_entry.side_effect = RuntimeError("unqualified")
    else:
        connection.get_transaction.return_value = object()
    with pytest.raises((bootstrap.BootstrapRefused, RuntimeError)):
        bootstrap.bootstrap(declarations, expected_database="academy", verify_only=False)
    root.commit.assert_not_called()
    root.rollback.assert_called()


def test_cli_refusal_does_not_print_driver_or_connection_material(monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise RuntimeError("postgresql://sensitive:material@host/private")

    monkeypatch.setattr(bootstrap, "bootstrap", refuse)
    assert bootstrap.main(["--expect-database", "academy"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "CI composed database bootstrap refused; discard and replay required\n"
