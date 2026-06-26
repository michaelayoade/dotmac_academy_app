"""Tests for cookie-based web auth (Task 3)."""

from __future__ import annotations


def test_login_sets_cookie_and_protects(app_client, admin_session, tenant_a):
    # Seed a Person + UserCredential for tenant_a directly.
    from app.models.auth import UserCredential
    from app.models.person import Person
    from app.services.security import hash_password

    p = Person(tenant_id=tenant_a.id, email="s@alpha.edu", first_name="Sam", last_name="Lee")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=p.id,
            email="s@alpha.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}

    # (a) Unauthenticated GET of a protected route redirects to /login.
    r = app_client.get("/account", headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)

    # The CSRF middleware sets a csrf_token cookie on every safe (GET) response.
    # Subsequent POSTs must double-submit it as the x-csrf-token header.
    csrf = r.cookies.get("csrf_token") or app_client.cookies.get("csrf_token", "")

    # (b) POST /login with valid form creds returns 303 and sets a session cookie.
    r = app_client.post(
        "/login",
        headers={**h, "x-csrf-token": csrf},
        data={"email": "s@alpha.edu", "password": "password1"},
        follow_redirects=False,
    )
    assert r.status_code == 303 and "session" in r.cookies
