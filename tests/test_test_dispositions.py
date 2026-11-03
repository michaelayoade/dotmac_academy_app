"""Enforce docs/inventories/test_dispositions.toml (pure; no database, no network).

Retired tests stay retired, protected suites cannot be retired, and every "duplicate"
claim names the Starter test that covers the behaviour together with the locked wheel
version it was checked against. A dotmac-learning / dotmac-kernel bump in poetry.lock
therefore fails here until the covering tests are re-verified and the inventory updated.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/inventories/test_dispositions.toml"
LOCK = ROOT / "poetry.lock"
WEIGHTS = ROOT / "scripts/ci_test_weights.json"
SKIP_ALLOWLIST = ROOT / "tests/ci_skip_allowlist.txt"

CLASSES = {"duplicate", "duplicate-internal", "obsolete"}
PACKAGES = {"dotmac-learning", "dotmac-kernel"}
SHA = re.compile(r"^[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def inventory() -> dict:
    return tomllib.loads(INVENTORY.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def locked() -> dict[str, str]:
    packages = tomllib.loads(LOCK.read_text(encoding="utf-8"))["package"]
    return {p["name"]: p["version"] for p in packages if p["name"] in PACKAGES}


def _retired(inventory):
    return inventory.get("retired", [])


def _rewritten(inventory):
    return inventory.get("rewritten", [])


def _protected(inventory) -> set[str]:
    table = inventory["protected"]
    return {path for paths in table.values() for path in paths}


def _module_defs(path: str) -> set[str]:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _coverings(inventory):
    for entry in [*_retired(inventory), *_rewritten(inventory)]:
        for covering in entry.get("covering", []):
            yield entry.get("path") or entry.get("old_path"), covering


def test_inventory_meta_and_shape(inventory):
    assert inventory["meta"]["starter_repo"] == "michaelayoade/dotmac_starter_mt"
    assert inventory["meta"]["approved_by"] == "Michael"
    assert _retired(inventory), "the inventory must record the approved retirements"
    seen = [e["path"] for e in _retired(inventory)]
    assert len(seen) == len(set(seen)), "a path is retired twice"


def test_every_retired_path_is_absent(inventory):
    weights = json.loads(WEIGHTS.read_text(encoding="utf-8"))
    weighted = set(weights["files"]) | set(weights["split"])
    allowlist = SKIP_ALLOWLIST.read_text(encoding="utf-8") if SKIP_ALLOWLIST.exists() else ""
    for entry in _retired(inventory):
        path = entry["path"]
        assert path.startswith("tests/") and path.endswith(".py"), path
        assert not (ROOT / path).exists(), f"{path} is retired but present"
        assert path not in weighted, f"{path} is retired but still in ci_test_weights.json"
        assert path not in allowlist, f"{path} is retired but named in the skip allowlist"


def test_every_retirement_records_class_reason_and_evidence(inventory):
    for entry in _retired(inventory):
        path = entry["path"]
        assert entry.get("class") in CLASSES, f"{path}: class must be one of {sorted(CLASSES)}"
        assert str(entry.get("reason", "")).strip(), f"{path}: reason missing"
        assert str(entry.get("evidence", "")).strip(), f"{path}: evidence missing"
        assert entry["evidence"].startswith(("verified", "inferred")), f"{path}: evidence must say verified or inferred"
        assert SHA.match(entry.get("retired_blob_sha", "")), f"{path}: retired_blob_sha missing"


def test_internal_duplicates_name_their_twin_and_every_test_is_defined_there(inventory):
    internal = [e for e in _retired(inventory) if e.get("class") == "duplicate-internal"]
    assert internal
    for entry in internal:
        path = entry["path"]
        assert entry.get("kept_twin"), f"{path}: duplicate-internal needs kept_twin"
        assert entry["kept_twin"] != path and (ROOT / entry["kept_twin"]).is_file(), f"{path}: twin missing"
        names = entry.get("tests") or []
        assert names, f"{path}: duplicate-internal needs the list of duplicated tests"
        missing = set(names) - _module_defs(entry["kept_twin"])
        assert not missing, f"{path}: not defined in {entry['kept_twin']}: {sorted(missing)}"


def test_obsolete_retirements_record_evidence(inventory):
    for entry in _retired(inventory):
        if entry["class"] == "obsolete":
            assert str(entry.get("evidence", "")).strip(), entry["path"]


def test_duplicates_name_a_starter_test_checked_against_the_locked_wheel(inventory):
    duplicates = [e for e in [*_retired(inventory), *_rewritten(inventory)] if e.get("class") == "duplicate"]
    assert duplicates
    for entry in duplicates:
        name = entry.get("path") or entry.get("old_path")
        covering = entry.get("covering", [])
        assert covering, f"{name}: a duplicate needs at least one covering Starter test"
    for name, covering in _coverings(inventory):
        assert covering["repo"] == inventory["meta"]["starter_repo"], f"{name}: covering test must be in Starter"
        assert covering["package"] in PACKAGES, name
        assert covering["tag"] == f"{covering['package']}-v{covering['locked_version']}", (
            f"{name}: tag must be the one for the recorded version"
        )
        assert covering["file"].startswith("tests/") and covering["file"].endswith(".py"), name
        assert covering["test"].startswith("test_"), name
        assert SHA.match(covering["blob_sha_at_tag"]), f"{name}: blob_sha_at_tag missing"


def test_kept_twins_and_replacements_exist(inventory):
    for entry in _retired(inventory):
        for key in ("kept_twin", "kept_adapter_test"):
            if key in entry:
                assert (ROOT / entry[key]).is_file(), f"{entry['path']}: {key} {entry[key]} is missing"
    for entry in _rewritten(inventory):
        assert (ROOT / entry["old_path"]).is_file(), f"{entry['old_path']}: rewritten file must remain"
        assert entry["replacement"], entry["old_path"]
        for node in entry["replacement"]:
            path, _, name = node.partition("::")
            assert (ROOT / path).is_file(), f"{node}: file missing"
            assert name in _module_defs(path), f"{node}: no module-level def of that name"


def test_no_protected_suite_is_retired(inventory):
    protected = _protected(inventory)
    assert protected, "the protected list must not be empty"
    for entry in _retired(inventory):
        assert entry["path"] not in protected, f"{entry['path']} is a protected suite and cannot be retired"
    for path in sorted(protected):
        assert (ROOT / path).is_file(), f"protected suite {path} is missing from tests/"


def test_protected_list_covers_the_data_move_and_bug_guard_suites(inventory):
    protected = _protected(inventory)
    must_hold = {
        "tests/test_academy_retained_adoption.py",
        "tests/test_academy_retained_schema.py",
        "tests/test_academy_retained_history.py",
        "tests/test_account_token_identity_adoption.py",
        "tests/architecture/test_academy_web_facet.py",
        "tests/test_display_settings.py",
        "tests/services/test_credential_lifecycle.py",
        "tests/test_catalog_json_codec.py",
        "tests/test_historical_runner_refusal_diagnostics.py",
        "tests/test_hosted_container_inspect_identity.py",
        "tests/test_hosted_context_refusal_diagnostics.py",
        "tests/test_identity_history_refusal_diagnostics.py",
        "tests/test_identity_history_source_composition.py",
        "tests/test_lab_retained_catalog_projection.py",
        "tests/test_product_provenance_successor_boundary.py",
        "tests/test_retained_successor_acl_packets.py",
        "tests/test_successor_acl_propagation.py",
        "tests/test_tenancy_binding.py",
        "tests/web/test_role_admission.py",
    }
    assert must_hold <= protected


def test_locked_wheel_versions_match_the_recorded_versions(inventory, locked):
    assert set(locked) == PACKAGES, "poetry.lock must pin both dotmac-learning and dotmac-kernel"
    for name, covering in _coverings(inventory):
        assert covering["locked_version"] == locked[covering["package"]], (
            f"{name}: poetry.lock pins {covering['package']} {locked[covering['package']]} but the covering test "
            f"was checked against {covering['locked_version']}; re-verify the Starter tests and update the inventory"
        )
