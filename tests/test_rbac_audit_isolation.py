"""RBAC and audit isolation canaries."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import client_for

PASSWORD = "correct horse battery staple"


def test_cross_tenant_role_assignment_returns_404(
    app_client: TestClient,
    tenant_a,
    tenant_b,
):
    a = client_for(app_client, tenant_a.slug)
    a_token = _register_and_login(a, "admin-a@rbac.example.com")
    role_id = _create_role(a, a_token, "support")["id"]

    b = client_for(TestClient(app_client.app), tenant_b.slug)
    b_person_id = b.post(
        "/auth/register",
        json={
            "email": "user-b@rbac.example.com",
            "password": PASSWORD,
            "first_name": "User",
            "last_name": "B",
        },
    ).json()["id"]

    response = a.post(
        "/rbac/role-grants",
        headers={"Authorization": f"Bearer {a_token}"},
        json={"person_id": b_person_id, "role_id": role_id},
    )
    assert response.status_code == 404


def test_audit_events_from_tenant_a_invisible_to_tenant_b(
    app_client: TestClient,
    tenant_a,
    tenant_b,
):
    a = client_for(app_client, tenant_a.slug)
    a_token = _register_and_login(a, "audit-a@rbac.example.com")
    _create_role(a, a_token, "audited-role")

    a_events = a.get("/rbac/audit-events", headers={"Authorization": f"Bearer {a_token}"})
    assert a_events.status_code == 200
    assert [event["action"] for event in a_events.json()] == ["role.create"]

    b = client_for(TestClient(app_client.app), tenant_b.slug)
    b_token = _register_and_login(b, "audit-b@rbac.example.com")
    b_events = b.get("/rbac/audit-events", headers={"Authorization": f"Bearer {b_token}"})
    assert b_events.status_code == 200
    assert b_events.json() == []


def _register_and_login(client: TestClient, email: str) -> str:
    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "first_name": "Admin",
            "last_name": "User",
        },
    )
    assert register.status_code == 201, register.text

    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _create_role(client: TestClient, token: str, slug: str) -> dict[str, object]:
    response = client.post(
        "/rbac/roles",
        headers={"Authorization": f"Bearer {token}"},
        json={"slug": slug, "name": slug.replace("-", " ").title()},
    )
    assert response.status_code == 201, response.text
    return response.json()
