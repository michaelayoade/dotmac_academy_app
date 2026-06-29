"""Cross-tenant isolation canaries.

These tests are the load-bearing invariant for the whole architecture. If they fail,
something is wrong at the routing, application, or RLS layer — and the failure mode
is "data leak between customers", which is unacceptable.

Every new tenant-scoped table MUST add a parallel test in this file (or sibling).

The tests run against a real Postgres because RLS doesn't exist in SQLite. Set
`TEST_DATABASE_URL` to a disposable Postgres before running.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import client_for

PASSWORD = "correct horse battery staple"


def test_person_created_in_tenant_a_invisible_to_tenant_b(
    app_client: TestClient,
    tenant_a,
    tenant_b,
):
    a = client_for(app_client, tenant_a.slug)
    resp = _register(a, "alice@a.example.com")
    assert resp.status_code == 201, resp.text
    person_id = resp.json()["id"]

    # From tenant B's subdomain, GET by exact ID must 404.
    b = client_for(TestClient(app_client.app), tenant_b.slug)
    b_token = _register_and_login(b, "reader@b.example.com")
    auth = {"Authorization": f"Bearer {b_token}"}
    assert b.get(f"/people/{person_id}", headers=auth).status_code == 404
    # And listing must not include the person.
    listing = b.get("/people", headers=auth).json()
    assert person_id not in [p["id"] for p in listing]


def test_person_delete_from_other_tenant_returns_404(
    app_client: TestClient,
    tenant_a,
    tenant_b,
):
    a = client_for(app_client, tenant_a.slug)
    resp = _register(a, "bob@a.example.com")
    assert resp.status_code == 201, resp.text
    person_id = resp.json()["id"]
    a_token = _login(a, "bob@a.example.com")

    # Delete from tenant B context — must 404.
    b = client_for(TestClient(app_client.app), tenant_b.slug)
    b_token = _register_and_login(b, "deleter@b.example.com")
    assert b.delete(
        f"/people/{person_id}",
        headers={"Authorization": f"Bearer {b_token}"},
    ).status_code == 404

    # Person still exists in tenant A.
    a2 = client_for(TestClient(app_client.app), tenant_a.slug)
    assert a2.get(
        f"/people/{person_id}",
        headers={"Authorization": f"Bearer {a_token}"},
    ).status_code == 200


def test_email_can_be_reused_across_tenants(
    app_client: TestClient,
    tenant_a,
    tenant_b,
):
    """Same email in two tenants is two distinct people — see ADR D1."""
    a = client_for(app_client, tenant_a.slug)
    r1 = _register(a, "shared@x.example.com", first_name="A")
    assert r1.status_code == 201, r1.text

    b = client_for(TestClient(app_client.app), tenant_b.slug)
    r2 = _register(b, "shared@x.example.com", first_name="B")
    assert r2.status_code == 201, r2.text

    # And they have different IDs.
    assert r1.json()["id"] != r2.json()["id"]


def _register(client: TestClient, email: str, first_name: str = "Test"):
    return client.post(
        "/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "first_name": first_name,
            "last_name": "User",
        },
    )


def _login(client: TestClient, email: str) -> str:
    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _register_and_login(client: TestClient, email: str) -> str:
    register = _register(client, email)
    assert register.status_code == 201, register.text
    return _login(client, email)
