"""Ratchets for ADR 0009's accepted database identity and lineage boundary.

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
import re
import tomllib
from uuid import UUID

import pytest
import sqlalchemy as sa
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir

from app.canonical_models import kernel_owned_tables, product_owned_tables

ROOT = pathlib.Path(__file__).resolve().parents[2]
INVENTORY_PATH = ROOT / "docs" / "inventories" / "kernel_identity_lineage_cutover.toml"
BASELINE_PATH = pathlib.Path(__file__).with_name("kernel_duplication_baseline.txt")
ACADEMY_VERSIONS = ROOT / "alembic" / "versions"
PERSON_IDENTITY_ALIASES = {
    ("attempt_grants", "granted_by"),
    ("lab_operations", "requested_by"),
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


# The legacy Academy-owned identity tables below no longer exist as Academy
# models: the composed tree gets them from the installed Kernel under party
# spellings (audit_events.actor_party_id, auth_sessions/user_credentials
# party_id, party_role_grants). The inventory keeps them as the legacy design
# baseline for the cutover; the composed census does not see them.
RETIRED_LEGACY_IDENTITY_COLUMNS = {
    ("audit_events", "actor_person_id"),
    ("auth_sessions", "person_id"),
    ("person_roles", "person_id"),
    ("user_credentials", "person_id"),
}


def _composed_tables() -> dict[str, sa.Table]:
    """Product-owned + Learning-owned + Kernel-owned tables of the D1 graph.

    app.models registers nothing in the composed tree, so the census reads the
    explicit owner declarations instead of an Academy Base.metadata.
    """
    import importlib

    for module in ("curriculum_models", "attempt_models", "participation_models", "delivery_models", "models"):
        importlib.import_module(f"dotmac_learning.{module}")
    from dotmac_learning.models import KernelBase

    learning = [table for key, table in KernelBase.metadata.tables.items() if key.startswith("mod_learning.")]
    tables: dict[tuple[str, str], sa.Table] = {}
    for table in (*product_owned_tables(), *learning, *kernel_owned_tables()):
        tables.setdefault((table.schema or "public", table.name), table)
    by_name: dict[str, sa.Table] = {}
    for table in tables.values():
        assert table.name not in by_name, f"table name collides across owners: {table.name}"
        by_name[table.name] = table
    return by_name


def _person_columns() -> dict[tuple[str, str], str]:
    found: dict[tuple[str, str], str] = {}
    for table in _composed_tables().values():
        for column in table.columns:
            if "person" not in column.name and (table.name, column.name) not in PERSON_IDENTITY_ALIASES:
                continue
            # Strong = a database FK to the canonical party identity (formerly people.*).
            has_party_fk = any(
                element.parent.name == column.name
                and element.target_fullname.rsplit(".", 2)[-2] in {"parties", "party_persons"}
                for constraint in table.foreign_key_constraints
                for element in constraint.elements
            )
            found[(table.name, column.name)] = "strong" if has_party_fk else "logical"
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
    # The inventory still carries the 30 legacy design coordinates; the composed
    # D1 graph exposes exactly those minus the four now Kernel-owned party tables.
    assert len(planned) == 30
    assert RETIRED_LEGACY_IDENTITY_COLUMNS <= set(planned)
    composed = _person_columns()
    assert {key: value for key, value in planned.items() if key not in RETIRED_LEGACY_IDENTITY_COLUMNS} == composed
    assert len(composed) == 26
    assert list(composed.values()).count("strong") == 10
    assert list(composed.values()).count("logical") == 16
    assert PERSON_IDENTITY_ALIASES <= set(composed)


def test_lab_requester_is_nullable_human_attribution_not_worker_fencing() -> None:
    references = {
        (entry["table"], entry["column"]): entry
        for entry in _inventory()["identity_reference"]
    }
    requester = references[("lab_operations", "requested_by")]
    assert requester == {
        "table": "lab_operations",
        "column": "requested_by",
        "current_integrity": "logical",
        "disposition": "retain_human_semantics",
        "nullable": True,
        "value_semantics": "person_uuid_for_user_request_null_for_automated_request",
        "introduced_by": "0055_lab_operations",
        "excluded_worker_identity": "lab_operations.claimed_by",
    }
    columns = _composed_tables()["lab_operations"].c
    assert columns.requested_by.nullable
    assert columns.requested_by.type.python_type is UUID
    assert columns.claimed_by.type.python_type is str
    assert ("lab_operations", "claimed_by") not in references


def test_source_refresh_does_not_relabel_historical_design_as_production_proof() -> None:
    inventory = _inventory()
    refreshed = inventory["source_revalidation"]
    assert refreshed["evidence"] == "source_only"
    assert refreshed["production_cutover_proven"] is False
    assert re.fullmatch(r"[a-f0-9]{40}", refreshed["academy_revision"])
    decision = "docs/adr/0009-kernel-identity-and-lineage-cutover.md"
    assert inventory["decision"] == decision
    assert (ROOT / decision).is_file()
    assert (ROOT / "docs/adr/0008-lab-worker-database-role.md").is_file()
    assert not (ROOT / "docs/adr/0008-kernel-identity-and-lineage-cutover.md").exists()


def test_inventory_pins_the_installed_kernel_and_both_lineage_endpoints() -> None:
    inventory = _inventory()
    assert importlib.metadata.version(inventory["kernel_distribution"]) == inventory["kernel_version"]

    academy_heads, academy_roots = _heads_and_roots(ACADEMY_VERSIONS)
    assert academy_heads == {inventory["current_lineage"]["head"]}
    assert academy_roots == {inventory["current_lineage"]["root"]}

    kernel_heads, kernel_roots = _heads_and_roots(kernel_versions_dir())
    assert kernel_heads == {inventory["target_kernel_lineage"]["head"]}
    assert kernel_roots == {inventory["target_kernel_lineage"]["root"]}


def test_adoption_strategy_composes_proven_patterns_without_copying_product_schemas() -> None:
    inventory = _inventory()
    strategy = inventory["adoption_strategy"]
    assert strategy == {
        "status": "accepted",
        "kernel_target_owner": "dotmac-kernel",
        "starter_role": "reference_assembly_and_schema_rehearsal_pattern",
        "legacy_data_pattern": "dotmac_sub_evidence_bound_identity_backfill",
        "external_auth_pattern": "dotmac_erp_local_issuer_subject_binding",
        "copy_product_identity_schema": False,
        "starter_is_identity_system_of_record": False,
        "new_kernel_adoption_facility_before_reuse": False,
    }

    evidence = {
        entry["owner"]: (entry["concern"], entry["adopt"], entry["reject"])
        for entry in inventory["baseline_evidence"]
    }
    assert evidence == {
        "dotmac-kernel": (
            "canonical_security_identity",
            "tenant_party_subtypes_credentials_sessions_rbac_rls",
            "product_specific_identity_models",
        ),
        "dotmac_starter_mt": (
            "schema_and_lineage_adoption",
            "create_or_adopt_full_catalog_drift_rollback_rehearsals",
            "starter_as_identity_authority",
        ),
        "dotmac_sub": (
            "legacy_data_adoption",
            "audit_adjudication_digest_approval_serializable_receipt",
            "untenant_scoped_business_party_and_business_role_schema",
        ),
        "dotmac_erp": (
            "external_authentication",
            "local_issuer_subject_binding_and_local_authorization",
            "legacy_person_credential_session_rbac_schema",
        ),
    }


def test_sub_reference_lineage_gate_blocks_activation_but_not_rehearsal_design() -> None:
    gate = _inventory()["sub_reference_lineage_gate"]
    assert gate == {
        "source": "dotmac_starter_mt/docs/adr/0017-adoption-is-the-scarce-resource.md",
        "status": "pending_external_evidence",
        "blocks_academy_lineage_activation": True,
        "academy_may_design_rehearsals": True,
        "academy_may_activate_lineage": False,
        "plane": "tenant_plane_1",
        "expected_first_failure": "0001_initial_tenant_schema",
        "reference_evidence": "dotmac_starter_mt/docs/inventories/sub-lineage-dispositions.md",
    }


def test_vendor_platform_gate_cannot_satisfy_tenant_identity_adoption() -> None:
    inventory = _inventory()
    platform = inventory["platform_p11_gate"]
    assert platform["status"] == "met"
    assert platform["proves_sub_tenant_plane"] is False
    assert platform["proves_academy_identity_cutover"] is False
    prerequisites = inventory["kernel_adoption_prerequisites"]
    assert prerequisites["status"] == "pending_external_evidence"
    assert prerequisites["true_party_and_facet_contract_required"] is True
    assert prerequisites["published_floor_required"] is True
    assert prerequisites["facade_or_shadow_binding_satisfies_gate"] is False


def test_current_migration_tools_cannot_manufacture_kernel_execution_history() -> None:
    """Inspect real tooling, not just inventory declarations about stamping.

    There is no approved entry executor today. An implementation must update
    this ratchet with its independent-history/full-chain rehearsal evidence;
    a stamp call or direct version-table write is never that evidence.
    """
    paths = [ROOT / "alembic/env.py", ROOT / "app/cli.py"]
    paths.extend(ACADEMY_VERSIONS.glob("*.py"))
    paths.extend((ROOT / "app/migrations").rglob("*.py"))
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "alembic.command":
                assert all(alias.name != "stamp" for alias in node.names), path
            if isinstance(node, ast.Call):
                function = node.func
                name = function.attr if isinstance(function, ast.Attribute) else (
                    function.id if isinstance(function, ast.Name) else None
                )
                assert name != "stamp", f"version-history stamping in {path}:{node.lineno}"
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not re.search(r"\balembic\s+stamp\b", node.value, re.IGNORECASE), path
                assert not re.search(
                    r"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?alembic_version\b",
                    node.value, re.IGNORECASE,
                ), path
    for path in (ROOT / "deploy").rglob("*.sh"):
        assert not re.search(r"\balembic\s+stamp\b", path.read_text(encoding="utf-8")), path

    entry = _inventory()["canonical_kernel_entry"]
    assert entry["status"] == "unresolved"
    assert entry["entire_unchanged_chain_before_runtime_cutover"] is True
    assert entry["genuine_independent_history_required"] is True
    assert entry["legacy_version_row_substitutes_kernel_history"] is False
    assert entry["kernel_stamping_allowed"] is False
    assert entry["kernel_existence_skips_allowed"] is False
    assert entry["kernel_revisions_deferred_after_runtime_cutover"] is False


def test_shared_root_ddl_equivalence_does_not_establish_kernel_history() -> None:
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
    assert not (ROOT / "app" / "migrations" / "kernel_identity_adoption.py").exists()


def test_account_status_does_not_supply_identity_activation() -> None:
    amendment = _inventory()["account_state_amendment"]
    assert amendment["source"] == "people.status"
    assert amendment["owner"] == "assembly"
    assert amendment["preserve_exact_recognized_status"] is True
    assert amendment["account_status_is_party_activation"] is False
    assert amendment["explicit_identity_activation_provenance_required"] is True
    assert amendment["implicit_active_default_allowed"] is False


def test_canonical_entry_rehearsal_is_not_runtime_activation() -> None:
    rehearsal = _inventory()["canonical_entry_rehearsal"]
    assert rehearsal["status"] == "source_preparation"
    assert set(rehearsal["legacy_relations"]) == {
        "tenants",
        "tenant_domains",
        "people",
        "user_credentials",
        "auth_sessions",
        "roles",
        "person_roles",
        "audit_events",
    }
    assert len(rehearsal["legacy_relations"]) == 8
    assert rehearsal["legacy_version_relation"] == "alembic_version"
    for requirement in (
        "caller_owned_connection_and_transaction",
        "original_relation_and_incoming_fk_oids_preserved",
        "legacy_version_rows_preserved",
        "actual_per_revision_execution_evidence_required",
        "injected_failure_rollback_required",
    ):
        assert rehearsal[requirement] is True
    assert rehearsal["qualified"] is False
    assert rehearsal["runtime_activation_authorized"] is False
    assert _inventory()["canonical_kernel_entry"]["status"] == "unresolved"


@pytest.mark.parametrize(
    "field",
    [
        "account_status_is_party_activation",
        "implicit_active_default_allowed",
    ],
)
def test_account_activation_ratchet_rejects_a_planted_inference(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    planted = _inventory()
    planted["account_state_amendment"][field] = True
    monkeypatch.setitem(globals(), "_inventory", lambda: planted)
    with pytest.raises(AssertionError):
        test_account_status_does_not_supply_identity_activation()


@pytest.mark.parametrize("field", ["qualified", "runtime_activation_authorized"])
def test_rehearsal_ratchet_rejects_a_planted_activation_claim(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    planted = _inventory()
    planted["canonical_entry_rehearsal"][field] = True
    monkeypatch.setitem(globals(), "_inventory", lambda: planted)
    with pytest.raises(AssertionError):
        test_canonical_entry_rehearsal_is_not_runtime_activation()
