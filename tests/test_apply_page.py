"""Public apply page (GET form + POST intake)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import client_for


def test_apply_form_renders(app_client, tenant_a):
    a = client_for(app_client, tenant_a.slug)
    r = a.get("/apply")
    assert r.status_code == 200
    assert 'hx-post="/apply"' in r.text
    assert "csrf_token" in r.text  # the CSRF shim is present


def test_apply_post_creates_applicant(app_client, tenant_a):
    # Fresh client, no prior cookies -> CSRF middleware is a no-op, so a direct
    # POST exercises the handler + service wiring.
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    r = a.post(
        "/apply",
        data={
            "first_name": "Web",
            "last_name": "Applicant",
            "email": "web@a.ex",
            "phone": "0800",
            "program": "Fiber Academy",
        },
    )
    assert r.status_code == 200, r.text
    assert "Application received" in r.text
    # It landed in the admissions API too (same tenant).
    from tests.conftest import client_for as cf

    admin = cf(TestClient(app_client.app), tenant_a.slug)
    admin.post(
        "/auth/register",
        json={
            "email": "adm2@a.ex",
            "password": "correct horse battery staple",
            "first_name": "A",
            "last_name": "D",
        },
    )
    tok = admin.post(
        "/auth/login", json={"email": "adm2@a.ex", "password": "correct horse battery staple"}
    ).json()["access_token"]
    listed = admin.get("/admissions", headers={"Authorization": f"Bearer {tok}"}).json()
    assert any(x["email"] == "web@a.ex" for x in listed)


def test_apply_post_escapes_name(app_client, tenant_a):
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    r = a.post(
        "/apply",
        data={"first_name": "<script>x</script>", "last_name": "T", "email": "xss@a.ex"},
    )
    assert r.status_code == 200
    assert "<script>x</script>" not in r.text  # escaped
    assert "&lt;script&gt;" in r.text
