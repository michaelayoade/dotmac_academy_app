"""Migration config construction has one production and one fixture owner."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONFIG_OWNERS = frozenset({
    "app/migration_graph.py",
    # Reviewed fixture-only adapter owns genuine legacy/Kernel-only replay and
    # complete composed config adaptation, including supplied-connection hooks.
    "tests/fixtures/kernel_identity_entry/rehearsal.py",
})


def _qualified(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _config_calls(source):
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _qualified(node.func, aliases) == "alembic.config.Config":
            violations.append((node.lineno, "Alembic Config construction"))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "set_main_option":
            option = node.args[0] if node.args else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "name"), None)
            if isinstance(option, ast.Constant) and option.value in {"script_location", "version_locations"}:
                violations.append((node.lineno, f"migration {option.value} override"))
    return violations


def test_migration_config_construction_and_locations_have_explicit_owners():
    assert all((ROOT / owner).is_file() for owner in CONFIG_OWNERS)
    violations = []
    for directory in ("app", "tests", "scripts"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            if relative in CONFIG_OWNERS:
                continue
            violations.extend((relative, line, reason) for line, reason in _config_calls(path.read_text()))
    assert violations == []


@pytest.mark.parametrize("source", (
    "from alembic.config import Config\nConfig()",
    "from alembic.config import Config as MigrationConfig\nMigrationConfig()",
    "import alembic.config as migration\nmigration.Config()",
    "import alembic\nalembic.config.Config()",
    "cfg.set_main_option('script_location', 'partial')",
    "cfg.set_main_option('version_locations', 'partial')",
))
def test_config_guard_detects_aliases_and_partial_location_overrides(source):
    assert len(_config_calls(source)) == 1


def test_config_guard_ignores_logging_and_unrelated_config_classes():
    assert _config_calls("import logging\nlogging.basicConfig(level=20)") == []
    assert _config_calls("class Config: pass\nConfig()") == []


def test_composed_fixture_keeps_complete_graph_supplied_connection_and_failure_callback(tmp_path):
    from alembic.script import ScriptDirectory
    from app.migration_graph import ordinary_migration_config
    from tests.fixtures.kernel_identity_entry.rehearsal import FIXTURE, composed_config_for

    supplied_connection = object()
    applied = []
    cfg = composed_config_for(supplied_connection, tmp_path / "adapter", applied, fail_after=1)
    canonical = ordinary_migration_config()
    assert cfg.attributes["connection"] is supplied_connection
    assert cfg.attributes["academy_migration_locations"] == canonical.attributes["academy_migration_locations"]
    assert cfg.get_main_option("version_locations") == canonical.get_main_option("version_locations")
    assert (tmp_path / "adapter" / "env.py").read_bytes() == (FIXTURE / "env.py").read_bytes()
    scripts = ScriptDirectory.from_config(cfg)
    assert scripts.get_revision("a010_facilitator_nominations") is not None
    assert scripts.get_revision("lr_0010_question_bank_versions") is not None
    revision = "a003_account_token_identity"
    with pytest.raises(RuntimeError, match="injected canonical replay failure"):
        cfg.attributes["on_version_apply"](
            ctx=None, step=SimpleNamespace(up_revision_ids=(revision,)), heads=(), run_args={})
    assert len(applied) == 1 and applied[0].revision == revision
    assert applied[0].sha256 == hashlib.sha256(Path(scripts.get_revision(revision).path).read_bytes()).hexdigest()
