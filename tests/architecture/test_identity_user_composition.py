"""Academy-owned identity-user receipt composition."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSITION = ROOT / "docs/contracts/academy-identity-user-binding-v1.json"
APPLY_INPUT = ROOT / "docs/contracts/academy-application-lifecycle-v1/apply-input.json"


def test_composition_is_canonical_value_free_and_product_owned() -> None:
    payload = COMPOSITION.read_bytes()
    document = json.loads(payload)
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert payload == canonical
    assert "sha256:" + hashlib.sha256(payload).hexdigest() == (
        "sha256:bca5283c47869f553f387090c1deae919bdbfb5921e47a79f90e7190bb9d67a1"
    )
    assert document["schema"] == "dotmac.capability-composition/v1"
    assert document["owner_code"] == "dotmac_academy_app"
    assert document["composition_code"] == "academy.identity-user-binding.v1"
    assert "source_value" not in payload.decode()
    assert "target_value" not in payload.decode()


def test_only_provisioned_issuer_and_subject_feed_the_academy_binding() -> None:
    bindings = json.loads(COMPOSITION.read_bytes())["evidence_bindings"]
    assert {(item["source_pointer"], item["target_pointer"]) for item in bindings} == {
        ("/issuer_url", "/external_subject/issuer"),
        ("/subject", "/external_subject/subject"),
    }
    assert all(item["source_capability_code"] == "identity.user.lifecycle" for item in bindings)
    assert all(item["source_operation_code"] == "apply" for item in bindings)
    assert all(item["target_capability_code"] == "academy.application.lifecycle" for item in bindings)
    assert all(item["target_operation_code"] == "apply" for item in bindings)
    assert all(item["coverage"] == "each_target_exactly_one" for item in bindings)
    # The local provider registration is trusted configuration, not copied
    # evidence. No mapping is allowed to populate it from a provider receipt.
    assert all(item["target_pointer"] != "/external_subject/provider_binding" for item in bindings)


def test_composition_pins_the_actual_academy_apply_schema() -> None:
    apply_payload = APPLY_INPUT.read_bytes()
    digest = "sha256:" + hashlib.sha256(apply_payload).hexdigest()
    bindings = json.loads(COMPOSITION.read_bytes())["evidence_bindings"]
    assert all(item["target_input_schema_digest"] == digest for item in bindings)
    schema = json.loads(apply_payload)
    external = schema["properties"]["external_subject"]["properties"]
    assert external["issuer"]["type"] == "string"
    assert external["subject"]["type"] == "string"
