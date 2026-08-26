"""Architecture ratchets for Academy's local identity authority."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "app/services/external_identity.py"
PROTOCOL = ROOT / "app/services/oidc_login.py"
REGISTRATION = ROOT / "app/services/external_identity_config.py"
LIFECYCLE = ROOT / "app/services/managed_application_lifecycle.py"
MIGRATION = ROOT / "alembic/versions/0055_external_identity_authority.py"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {
        alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    }


def test_local_owner_imports_no_starter_identity_or_provider_client() -> None:
    imports = _imports(OWNER)
    assert all(not name.startswith("dotmac_kernel.external_identity") for name in imports)
    assert all(not name.startswith("dotmac_kernel.models") for name in imports)
    assert all(not name.startswith(("dotmac_auth_oidc", "httpx", "jwt")) for name in imports)


def test_protocol_path_uses_the_published_adapter_and_no_local_verifier() -> None:
    imports = _imports(PROTOCOL)
    assert any(name.startswith("dotmac_auth_oidc") for name in imports)
    assert all(not name.startswith(("jwt", "jose", "httpx")) for name in imports)
    tree = ast.parse(PROTOCOL.read_text())
    calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "finalize_external_login" in calls
    assert attributes.isdisjoint({"email", "roles", "groups", "scopes", "claims"})


def test_login_and_disable_take_the_same_binding_lock() -> None:
    source = OWNER.read_text()
    tree = ast.parse(source)
    functions = {
        node.name: ast.get_source_segment(OWNER.read_text(), node) or ""
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert ".with_for_update()" in functions["finalize_external_login"]
    assert "start_session(" in functions["finalize_external_login"]
    assert ".with_for_update()" in functions["disable_external_identity_binding"]
    assert "_revoke_sessions_for_binding(" in functions["disable_external_identity_binding"]
    assert "AuthSession(" not in source
    assert ".commit(" not in source


def test_lifecycle_corroborates_process_held_provider_before_binding_mutation() -> None:
    registration_tree = ast.parse(REGISTRATION.read_text())
    imports = _imports(REGISTRATION)
    assert imports.isdisjoint({"os", "httpx", "requests", "dotmac_auth_oidc"})
    attributes = {node.attr for node in ast.walk(registration_tree) if isinstance(node, ast.Attribute)}
    assert {"oidc_provider_binding", "oidc_issuer"} <= attributes

    lifecycle_tree = ast.parse(LIFECYCLE.read_text())
    functions = {
        node.name: ast.get_source_segment(LIFECYCLE.read_text(), node) or ""
        for node in lifecycle_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "configuration_matches(" in functions["plan"]
    apply_source = functions["apply"]
    assert apply_source.index("configuration_matches(") < apply_source.index("bind_external_identity(")


def test_adapter_is_exactly_pinned_to_the_published_pilot() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["tool"]["poetry"]["dependencies"]["dotmac-auth-oidc"] == {
        "version": "0.1.0a1",
        "source": "forgejo",
    }


def test_schema_owns_identity_binding_provenance_and_shared_state() -> None:
    source = MIGRATION.read_text()
    for table in ("external_identity_bindings", "auth_sessions", "academy_oidc_login_states"):
        assert table in source
    assert "external_identity_binding_id" in source
    assert "ON DELETE RESTRICT" in source
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "DELETE" in source and "academy_oidc_login_states" in source
