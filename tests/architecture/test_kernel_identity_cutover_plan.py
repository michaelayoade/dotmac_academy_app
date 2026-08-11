"""Ratchets for ADR 0008's database identity and lineage boundary.

The ADR is deliberately design-only today. These tests make its evidence
executable: all existing kernel collisions and person-identity references must
be classified, the copied root must still be demonstrably the kernel root, and
no one may compose or mutate the target lineage before the PostgreSQL
rehearsals exist.
"""

from __future__ import annotations

import ast
import configparser
import importlib.metadata
import pathlib
import tomllib

from dotmac_kernel.migrations import versions_dir as kernel_versions_dir

import app.models
import app.models.auth
import app.models.person
import app.models.rbac  # noqa: F401  (not exported from app.models)
from app.models.base import Base

ROOT = pathlib.Path(__file__).resolve().parents[2]
INVENTORY_PATH = ROOT / "docs" / "inventories" / "kernel_identity_lineage_cutover.toml"
BASELINE_PATH = pathlib.Path(__file__).with_name("kernel_duplication_baseline.txt")
ACADEMY_VERSIONS = ROOT / "alembic" / "versions"
PERSON_IDENTITY_ALIASES = {
    ("attempt_grants", "granted_by"),
    ("success_queue_entries", "assigned_to"),
    ("success_queue_entries", "resolved_by"),
}


def _inventory() -> dict[str, object]:
    return tomllib.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def _literal_assignments(path: pathlib.Path) -> dict[str, object]:
    values: dict[str, object] = {}
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            try:
                values[target.id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                pass
    return values


def _revision_files(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    revisions: dict[str, pathlib.Path] = {}
    for path in directory.glob("*.py"):
        revision = _literal_assignments(path).get("revision")
        if isinstance(revision, str):
            assert revision not in revisions, f"duplicate revision {revision!r} in {directory}"
            revisions[revision] = path
    return revisions


def _heads_and_roots(directory: pathlib.Path) -> tuple[set[str], set[str]]:
    revisions = _revision_files(directory)
    parents: set[str] = set()
    roots: set[str] = set()
    for revision, path in revisions.items():
        down = _literal_assignments(path).get("down_revision")
        if down is None:
            roots.add(revision)
        elif isinstance(down, str):
            parents.add(down)
        elif isinstance(down, (list, tuple)):
            parents.update(parent for parent in down if isinstance(parent, str))
    return set(revisions) - parents, roots


def _function_contract(path: pathlib.Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: ast.dump(node, include_attributes=False)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _baseline() -> set[str]:
    return {
        line.strip()
        for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _person_columns() -> dict[tuple[str, str], str]:
    found: dict[tuple[str, str], str] = {}
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if "person" not in column.name and (table.name, column.name) not in PERSON_IDENTITY_ALIASES:
                continue
            has_people_fk = any(
                element.parent.name == column.name and element.target_fullname.startswith("people.")
                for constraint in table.foreign_key_constraints
                for element in constraint.elements
            )
            found[(table.name, column.name)] = "strong" if has_people_fk else "logical"
    return found


def test_every_remaining_kernel_collision_has_one_disposition() -> None:
    inventory = _inventory()
    model_edges = inventory["model_edge"]
    planned = {
        edge["academy_entry"]
        for edge in model_edges
        if edge["kind"] == "same_name_collision"
    }
    assert planned == _baseline()
    assert all(edge["target_owner"] == "kernel" for edge in model_edges)


def test_semantic_identity_edges_cannot_hide_behind_the_name_collision_ratchet() -> None:
    model_edges = _inventory()["model_edge"]
    planned = {
        edge["academy_entry"]
        for edge in model_edges
        if edge["kind"] != "same_name_collision"
    }
    assert planned == {
        "app/models/person.py:Person",
        "app/models/rbac.py:AuditEvent.actor_person_id",
        "app/models/rbac.py:PersonRole",
    }


def test_every_person_identity_column_is_classified_with_its_real_integrity() -> None:
    references = _inventory()["identity_reference"]
    planned = {
        (entry["table"], entry["column"]): entry["current_integrity"]
        for entry in references
    }
    assert len(planned) == len(references), "identity reference appears more than once"
    assert planned == _person_columns()
    assert len(planned) == 27
    assert list(planned.values()).count("strong") == 11
    assert list(planned.values()).count("logical") == 16
    assert PERSON_IDENTITY_ALIASES <= set(planned)


def test_inventory_pins_the_installed_kernel_and_both_lineage_endpoints() -> None:
    inventory = _inventory()
    assert importlib.metadata.version(inventory["kernel_distribution"]) == inventory["kernel_version"]

    academy_heads, academy_roots = _heads_and_roots(ACADEMY_VERSIONS)
    assert academy_heads == {inventory["current_lineage"]["head"]}
    assert academy_roots == {inventory["current_lineage"]["root"]}

    kernel_heads, kernel_roots = _heads_and_roots(kernel_versions_dir())
    assert kernel_heads == {inventory["target_kernel_lineage"]["head"]}
    assert kernel_roots == {inventory["target_kernel_lineage"]["root"]}


def test_the_shared_root_id_is_one_ddl_contract_not_two_independent_owners() -> None:
    inventory = _inventory()
    root_revision = inventory["current_lineage"]["root"]
    academy_root = ROOT / inventory["current_lineage"]["root_file"]
    kernel_root = _revision_files(kernel_versions_dir())[root_revision]

    assert _literal_assignments(academy_root)["revision"] == root_revision
    assert _literal_assignments(kernel_root)["revision"] == root_revision
    assert _function_contract(academy_root) == _function_contract(kernel_root)
    assert _literal_assignments(academy_root)["branch_labels"] is None
    assert _literal_assignments(kernel_root)["branch_labels"] == ("kernel",)


def test_design_only_status_forbids_an_early_lineage_or_identity_mutation() -> None:
    inventory = _inventory()
    assert inventory["status"] == "design_only"

    parser = configparser.ConfigParser()
    parser.read(ROOT / "alembic.ini", encoding="utf-8")
    assert not parser.get("alembic", "version_locations", fallback="", raw=True).strip()

    revisions = _revision_files(ACADEMY_VERSIONS)
    assert inventory["target_assembly_lineage"]["root"] not in revisions
    for path in revisions.values():
        assignments = _literal_assignments(path)
        labels = assignments.get("branch_labels") or ()
        assert inventory["target_assembly_lineage"]["branch_label"] not in labels

    migration_source = "\n".join(path.read_text(encoding="utf-8") for path in revisions.values())
    assert 'create_table("parties"' not in migration_source
    assert 'create_table("party_roles"' not in migration_source
    assert 'create_table("academy_person_profiles"' not in migration_source
    assert 'create_table("academy_login_security"' not in migration_source
