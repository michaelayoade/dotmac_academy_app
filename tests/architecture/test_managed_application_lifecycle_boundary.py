"""Structural boundary for the Academy managed-service port."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.managed_application_lifecycle import ApplicationLifecycleTarget
from app.services.managed_application_lifecycle import CAPABILITY_ID, STABLE_FAILURE_CODES

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "app/api/managed_application_lifecycle.py"
SERVICE = ROOT / "app/services/managed_application_lifecycle.py"
CONTRACT = ROOT / "docs/contracts/academy-application-lifecycle-v1.json"
SCHEMA_DIR = ROOT / "docs/contracts/academy-application-lifecycle-v1"
ORCHESTRATOR_FIELDS = {
    "expected_state",
    "expected_state_digest",
    "idempotency_key",
    "operation_ref",
    "plan_digest",
    "target",
    "target_digest",
}


def _declared_property_names(document: object) -> set[str]:
    if isinstance(document, dict):
        names = set(document.get("properties", {}))
        for value in document.values():
            names.update(_declared_property_names(value))
        return names
    if isinstance(document, list):
        names: set[str] = set()
        for value in document:
            names.update(_declared_property_names(value))
        return names
    return set()


def test_capability_is_product_namespaced() -> None:
    assert CAPABILITY_ID == "academy.application.lifecycle.v1"


def test_owner_contract_pins_every_checked_in_schema_document() -> None:
    payload = CONTRACT.read_bytes()
    document = json.loads(payload)
    assert document["schema"] == "dotmac.capability-contract/v1"
    assert document["owner_code"] == "dotmac_academy_app"
    assert document["capability_code"] == "academy.application.lifecycle"
    assert document["schema_version"] == 1
    assert [item["operation_code"] for item in document["operations"]] == [
        "apply",
        "cancel",
        "observe",
        "plan",
    ]
    schemas = {json.loads(path.read_bytes())["$id"]: path.read_bytes() for path in sorted(SCHEMA_DIR.glob("*.json"))}
    pinned_refs: set[str] = set()
    for operation in document["operations"]:
        for direction in ("input", "output"):
            reference = operation[f"{direction}_schema_ref"]
            pinned_refs.add(reference)
            digest = "sha256:" + hashlib.sha256(schemas[reference]).hexdigest()
            assert operation[f"{direction}_schema_digest"] == digest
    assert pinned_refs == set(schemas)


def test_capability_inputs_are_product_desired_values_not_the_http_ledger_envelope() -> None:
    schemas = {path.stem: json.loads(path.read_bytes()) for path in SCHEMA_DIR.glob("*-input.json")}
    desired = schemas["apply-input"]["properties"]
    assert set(desired) == {
        "desired_state",
        "external_subject",
        "person_id",
        "tenant_id",
    }
    assert schemas["plan-input"]["properties"] == desired
    assert schemas["apply-input"]["required"] == sorted(desired)
    assert schemas["plan-input"]["required"] == sorted(desired)

    identity = {key: desired[key] for key in ("external_subject", "person_id", "tenant_id")}
    for operation in ("cancel-input", "observe-input"):
        assert schemas[operation]["properties"] == identity
        assert schemas[operation]["required"] == sorted(identity)

    for document in schemas.values():
        assert _declared_property_names(document).isdisjoint(ORCHESTRATOR_FIELDS)


def test_capability_input_orchestrator_field_guard_is_sensitive() -> None:
    planted = {"properties": {"operation_ref": {"type": "string"}}}
    assert _declared_property_names(planted) & ORCHESTRATOR_FIELDS == {"operation_ref"}


def test_contract_keeps_external_identity_cutover_as_a_required_activation_gate() -> None:
    document = json.loads(CONTRACT.read_bytes())
    assert {
        "check_code": "academy.external-identity.binding-ready",
        "evidence_type": "boolean",
        "required": True,
        "stage": "activation",
    } in document["checks"]


def test_target_has_only_the_four_approved_identity_and_state_fields() -> None:
    assert set(ApplicationLifecycleTarget.model_fields) == {
        "tenant_id",
        "person_id",
        "desired_state",
        "external_subject",
    }
    assert set(ApplicationLifecycleTarget.model_fields["external_subject"].annotation.model_fields) == {
        "provider_binding",
        "issuer",
        "subject",
    }


@pytest.mark.parametrize(
    "forbidden",
    ["email", "first_name", "last_name", "roles", "groups", "scopes", "claims", "password", "employment", "enrolment"],
)
def test_target_rejects_every_forbidden_authority_field(forbidden: str) -> None:
    target = {
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "person_id": "00000000-0000-0000-0000-000000000002",
        "desired_state": "active",
        "external_subject": {
            "provider_binding": "customer-keycloak",
            "issuer": "https://idp.example.test/realms/customer",
            "subject": "subject-1",
        },
        forbidden: "forbidden",
    }
    with pytest.raises(ValidationError):
        ApplicationLifecycleTarget.model_validate(target)


def test_route_is_a_thin_adapter_without_queries() -> None:
    tree = ast.parse(API.read_text())
    forbidden_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"execute", "query", "scalars"}:
                forbidden_calls.append(node.func.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "select":
            forbidden_calls.append("select")
    assert forbidden_calls == []


def test_service_has_no_provider_io_or_identity_writer() -> None:
    tree = ast.parse(SERVICE.read_text())
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported_roots.isdisjoint({"httpx", "requests", "dotmac_auth_oidc"})
    assert "ExternalIdentityBinding" not in SERVICE.read_text()
    assert "UserCredential(" not in SERVICE.read_text()


def test_failure_vocabulary_is_closed() -> None:
    assert STABLE_FAILURE_CODES == {
        "expected_state_changed",
        "idempotency_conflict",
        "operation_cancelled",
        "operation_not_cancellable",
        "operation_not_found",
        "person_not_found",
        "plan_mismatch",
        "provider_binding_unknown",
        "tenant_mismatch",
    }
