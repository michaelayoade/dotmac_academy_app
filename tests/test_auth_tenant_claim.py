"""Auth tenant-claim canaries."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import client_for


def test_jwt_issued_for_tenant_a_rejected_on_tenant_b(
    app_client: TestClient,
    tenant_a,
    tenant_b,
):
    a = client_for(app_client, tenant_a.slug)
    register = a.post(
        "/auth/register",
        json={
            "email": "alice-auth@a.example.com",
            "password": "correct horse battery staple",
            "first_name": "Alice",
            "last_name": "Auth",
        },
    )
    assert register.status_code == 201, register.text

    login = a.post(
        "/auth/login",
        json={
            "email": "alice-auth@a.example.com",
            "password": "correct horse battery staple",
        },
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    assert a.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    b = client_for(TestClient(app_client.app), tenant_b.slug)
    rejected = b.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert rejected.status_code == 401
