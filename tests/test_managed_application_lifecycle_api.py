"""HTTP boundary tests for the managed lifecycle product port."""

from __future__ import annotations

import json
import time
from uuid import uuid4

from app.config import settings
from app.models.person import Person
from app.services.erp_integration_security import sign_request
from tests.conftest import client_for


def _install_provider(monkeypatch) -> None:
    monkeypatch.setattr(settings, "oidc_provider_binding", "customer-keycloak")
    monkeypatch.setattr(
        settings,
        "oidc_issuer",
        "https://idp.customer.example/realms/customer",
    )


def _signed(body: bytes, *, secret: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Signature-256": sign_request(secret=secret, timestamp=timestamp, body=body),
    }


def _target(tenant, person) -> dict[str, object]:
    return {
        "tenant_id": str(tenant.id),
        "person_id": str(person.id),
        "desired_state": "suspended",
        "external_subject": {
            "provider_binding": "customer-keycloak",
            "issuer": "https://idp.customer.example/realms/customer",
            "subject": "Subject-1",
        },
    }


def test_service_port_is_disabled_without_held_authentication(app_client, tenant_a):
    client = client_for(app_client, tenant_a.slug)
    body = b"{}"
    response = client.post(
        "/api/v1/integrations/application-lifecycle/plan",
        content=body,
        headers=_signed(body, secret="wrong"),
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "integration_disabled"


def test_strict_target_refuses_identity_and_authorization_fields(
    app_client,
    admin_session,
    tenant_a,
    monkeypatch,
):
    person = Person(
        tenant_id=tenant_a.id,
        email=f"{uuid4().hex}@lifecycle.test",
        first_name="Managed",
        last_name="Learner",
    )
    admin_session.add(person)
    admin_session.commit()
    secret = "test-only-managed-lifecycle-secret"
    monkeypatch.setattr(settings, "managed_lifecycle_inbound_hmac_secret", secret)
    payload = {
        "idempotency_key": "command-1",
        "target": {
            **_target(tenant_a, person),
            "email": "takeover@example.test",
            "roles": ["admin"],
        },
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    response = client_for(app_client, tenant_a.slug).post(
        "/api/v1/integrations/application-lifecycle/plan",
        content=body,
        headers=_signed(body, secret=secret),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_plan_apply_observe_round_trip_uses_signed_exact_bytes(
    app_client,
    admin_session,
    tenant_a,
    monkeypatch,
):
    _install_provider(monkeypatch)
    person = Person(
        tenant_id=tenant_a.id,
        email=f"{uuid4().hex}@lifecycle.test",
        first_name="Managed",
        last_name="Learner",
    )
    admin_session.add(person)
    admin_session.commit()
    secret = "test-only-managed-lifecycle-secret"
    monkeypatch.setattr(settings, "managed_lifecycle_inbound_hmac_secret", secret)
    client = client_for(app_client, tenant_a.slug)

    plan_payload = {"idempotency_key": "command-1", "target": _target(tenant_a, person)}
    plan_body = json.dumps(plan_payload, separators=(",", ":"), sort_keys=True).encode()
    planned = client.post(
        "/api/v1/integrations/application-lifecycle/plan",
        content=plan_body,
        headers=_signed(plan_body, secret=secret),
    )
    assert planned.status_code == 200, planned.text
    plan_result = planned.json()

    apply_payload = {
        **plan_payload,
        "operation_ref": plan_result["operation_ref"],
        "target_digest": plan_result["target_digest"],
        "expected_state_digest": plan_result["expected_state_digest"],
        "plan_digest": plan_result["plan_digest"],
    }
    apply_body = json.dumps(apply_payload, separators=(",", ":"), sort_keys=True).encode()
    applied = client.post(
        "/api/v1/integrations/application-lifecycle/apply",
        content=apply_body,
        headers=_signed(apply_body, secret=secret),
    )
    assert applied.status_code == 200, applied.text
    assert applied.json()["result_state"]["account_status"] == "suspended"

    observe_body = json.dumps(
        {"operation_ref": plan_result["operation_ref"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    observed = client.post(
        "/api/v1/integrations/application-lifecycle/observe",
        content=observe_body,
        headers=_signed(observe_body, secret=secret),
    )
    assert observed.status_code == 200, observed.text
    assert observed.json()["converged"] is True
    assert observed.json()["target"] == plan_result["target"]


def test_signature_is_over_the_exact_body(app_client, tenant_a, monkeypatch):
    secret = "test-only-managed-lifecycle-secret"
    monkeypatch.setattr(settings, "managed_lifecycle_inbound_hmac_secret", secret)
    signed = b'{"operation_ref":"00000000-0000-0000-0000-000000000000"}'
    changed = b'{ "operation_ref":"00000000-0000-0000-0000-000000000000"}'
    response = client_for(app_client, tenant_a.slug).post(
        "/api/v1/integrations/application-lifecycle/observe",
        content=changed,
        headers=_signed(signed, secret=secret),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_signature"
