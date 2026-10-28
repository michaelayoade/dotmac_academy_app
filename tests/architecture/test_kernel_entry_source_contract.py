"""Source canaries for a fixture-only canonical-entry rehearsal, not adoption."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "kernel_identity_entry"
MANIFEST_SHA256 = "0c6f477bcdb8477a6e34c6b15809f71f7382c2cc8ce3b43e72c387daa6879a37"


def test_legacy_source_is_the_complete_immutable_accepted_096_closure():
    manifest = FIXTURE / "manifest.json"
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == MANIFEST_SHA256
    data = json.loads(manifest.read_text())
    assert data["ref"] == "0968881fc40ad86b3abfea2fc40044dd2dbf47c9"
    expected = {
        entry["path"]: entry
        for entry in data["files"]
        if entry["path"].startswith("alembic/versions/")
    }
    assert len(expected) == 62
    actual = {str(path.relative_to(FIXTURE)) for path in (FIXTURE / "alembic/versions").glob("*.py")}
    assert actual == set(expected)
    for relative, entry in expected.items():
        content = (FIXTURE / relative).read_bytes()
        assert len(content) == entry["bytes"]
        assert hashlib.sha256(content).hexdigest() == entry["sha256"]
        ast.parse(content)


def test_rehearsal_has_no_stamp_or_production_activation_import():
    paths = [FIXTURE / "rehearsal.py", FIXTURE / "env.py", ROOT / "tests/test_kernel_identity_entry.py"]
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"stamp", "commit", "create_all"}
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("app.")


def test_fixture_environment_uses_only_the_injected_connection():
    source = (FIXTURE / "env.py").read_text()
    assert 'config.attributes["connection"]' in source
    assert 'version_table_schema="public"' in source
    assert "on_version_apply" in source
    assert "create_engine" not in source
    assert "engine_from_config" not in source
