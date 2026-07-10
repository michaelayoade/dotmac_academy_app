"""Admissions: cross-tenant isolation + pipeline canaries.

Mirrors the other ``test_*_isolation.py`` files. Requires a migrated disposable
Postgres (TEST_DATABASE_URL); skipped otherwise by the shared fixtures.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import client_for

_PW = "correct horse battery staple"


def _admin_token(client: TestClient, slug: str) -> dict[str, str]:
    """Register (first user becomes admin) + login on ``slug``'s subdomain."""
    c = client_for(client, slug)
    c.post(
        "/auth/register",
        json={
            "email": f"adm@{slug}.example",
            "password": _PW,
            "first_name": "Ad",
            "last_name": "Min",
        },
    )
    tok = c.post("/auth/login", json={"email": f"adm@{slug}.example", "password": _PW}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def test_public_apply_creates_applicant(app_client, tenant_a):
    a = client_for(app_client, tenant_a.slug)
    r = a.post(
        "/admissions/apply",
        json={
            "email": "ANN@a.example",
            "first_name": "Ann",
            "last_name": "A",
            "phone": "0800",
            "program": "Fiber Academy",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "applied"
    assert body["email"] == "ann@a.example"  # normalised lower-case


def test_apply_is_idempotent_on_email(app_client, tenant_a):
    a = client_for(app_client, tenant_a.slug)
    first = a.post(
        "/admissions/apply", json={"email": "dup@a.example", "first_name": "D", "last_name": "One"}
    )
    again = a.post(
        "/admissions/apply", json={"email": "dup@a.example", "first_name": "D", "last_name": "Two"}
    )
    assert first.status_code == 201 and again.status_code == 201
    assert first.json()["id"] == again.json()["id"]


def test_applicant_isolated_between_tenants(app_client, tenant_a, tenant_b):
    a = client_for(app_client, tenant_a.slug)
    app_id = a.post(
        "/admissions/apply",
        json={"email": "sec@a.example", "first_name": "S", "last_name": "Ec"},
    ).json()["id"]

    b = client_for(TestClient(app_client.app), tenant_b.slug)
    auth_b = _admin_token(app_client, tenant_b.slug)
    assert b.get(f"/admissions/{app_id}", headers=auth_b).status_code == 404
    listed = b.get("/admissions", headers=auth_b).json()
    assert app_id not in [x["id"] for x in listed]


def test_pipeline_transitions_and_guards(app_client, tenant_a):
    a = client_for(app_client, tenant_a.slug)
    auth = _admin_token(app_client, tenant_a.slug)
    app_id = a.post(
        "/admissions/apply",
        json={"email": "flow@a.example", "first_name": "F", "last_name": "Low"},
    ).json()["id"]

    # Illegal jump applied -> enrolled is rejected.
    bad = a.post(f"/admissions/{app_id}/transition", json={"to_status": "enrolled"}, headers=auth)
    assert bad.status_code == 400

    # Walk the happy path applied -> screened -> accepted -> onboarding.
    for nxt in ("screened", "accepted", "onboarding"):
        r = a.post(f"/admissions/{app_id}/transition", json={"to_status": nxt}, headers=auth)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == nxt

    # Unknown status -> 400.
    assert (
        a.post(
            f"/admissions/{app_id}/transition", json={"to_status": "banana"}, headers=auth
        ).status_code
        == 400
    )


def test_apply_is_public_but_list_requires_admin(app_client, tenant_a):
    a = client_for(app_client, tenant_a.slug)
    # apply works with no auth header
    assert (
        a.post(
            "/admissions/apply",
            json={"email": "pub@a.example", "first_name": "P", "last_name": "Ub"},
        ).status_code
        == 201
    )
    # listing without auth is rejected
    assert a.get("/admissions").status_code in (401, 403)
