"""Tests for cookie-based web auth (Task 3)."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient


def _seed_web_user(admin_session, tenant, *, email: str = "return@alpha.edu"):
    from app.models.auth import UserCredential
    from app.models.person import Person
    from app.services.security import hash_password

    person = Person(tenant_id=tenant.id, email=email, first_name="Return", last_name="Tester")
    admin_session.add(person)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=person.id,
            email=email,
            password_hash=hash_password("password1"),
        )
    )
    admin_session.commit()
    return person


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


def test_login_resumes_protected_page_and_session_cookie_survives_fresh_client(
    app_client,
    admin_session,
    tenant_a,
):
    _seed_web_user(admin_session, tenant_a)
    headers = {"Host": "alpha.localhost"}

    protected = app_client.get("/account?panel=security", headers=headers, follow_redirects=False)
    assert protected.status_code == 303
    login_url = protected.headers["location"]
    assert parse_qs(urlsplit(login_url).query)["next"] == ["/account?panel=security"]

    login_page = app_client.get(login_url, headers=headers, follow_redirects=False)
    assert 'name="next" value="/account?panel=security"' in login_page.text
    csrf = login_page.cookies.get("csrf_token") or app_client.cookies.get("csrf_token", "")

    logged_in = app_client.post(
        "/login",
        headers={**headers, "x-csrf-token": csrf},
        data={
            "email": "return@alpha.edu",
            "password": "password1",
            "next": "/account?panel=security",
        },
        follow_redirects=False,
    )
    assert logged_in.status_code == 303
    assert logged_in.headers["location"] == "/account?panel=security"
    set_cookie = logged_in.headers["set-cookie"].lower()
    assert "max-age=3600" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie

    # A new client represents a fresh web process/browser connection: the
    # durable database session, not process memory, remains authoritative.
    fresh_client = TestClient(app_client.app)
    fresh_client.cookies.set("session", logged_in.cookies["session"])
    resumed = fresh_client.get("/account", headers=headers, follow_redirects=False)
    assert resumed.status_code == 200


def test_expired_post_returns_to_same_origin_form_page(app_client, tenant_a):
    headers = {"Host": "alpha.localhost"}
    login_page = app_client.get("/login", headers=headers)
    csrf = login_page.cookies.get("csrf_token") or app_client.cookies.get("csrf_token", "")

    response = app_client.post(
        "/account",
        headers={
            **headers,
            "referer": "http://alpha.localhost/account?panel=profile",
            "x-csrf-token": csrf,
        },
        data={"first_name": "No", "last_name": "Session"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query)["next"] == [
        "/account?panel=profile"
    ]


@pytest.mark.parametrize(
    "target",
    [
        "https://attacker.example/phish",
        "//attacker.example/phish",
        "/\\attacker.example/phish",
        "/login",
        "/logout",
        "/account#fragment",
    ],
)
def test_login_rejects_unsafe_return_target(app_client, admin_session, tenant_a, target):
    _seed_web_user(admin_session, tenant_a, email="safe-return@alpha.edu")

    response = app_client.post(
        "/login",
        headers={"Host": "alpha.localhost"},
        data={"email": "safe-return@alpha.edu", "password": "password1", "next": target},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_session_rejection_log_has_reason_but_never_cookie(
    app_client,
    tenant_a,
    caplog,
):
    raw_cookie = "sensitive-session-value"
    app_client.cookies.set("session", raw_cookie)

    with caplog.at_level(logging.INFO, logger="app.services.web_auth"):
        response = app_client.get(
            "/account",
            headers={"Host": "alpha.localhost"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "reason=session_not_found" in caplog.text
    assert raw_cookie not in caplog.text


def test_login_canonicalizes_email_and_ignores_credential_email_drift(
    app_client,
    admin_session,
    tenant_a,
):
    from app.models.auth import UserCredential
    from app.models.person import Person
    from app.services.security import hash_password

    person = Person(
        tenant_id=tenant_a.id,
        email="Mixed.Case@Alpha.EDU ",
        first_name="Mixed",
        last_name="Case",
    )
    admin_session.add(person)
    admin_session.flush()
    credential = UserCredential(
        tenant_id=tenant_a.id,
        person_id=person.id,
        email="stale-login@alpha.edu",
        password_hash=hash_password("password1"),
    )
    admin_session.add(credential)
    admin_session.commit()

    response = app_client.post(
        "/login",
        headers={"Host": "alpha.localhost"},
        data={"email": "  MIXED.case@alpha.edu  ", "password": "password1"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    admin_session.refresh(person)
    admin_session.refresh(credential)
    assert person.email == "mixed.case@alpha.edu"
    assert credential.email == person.email


def test_logout_revokes_server_side_session(app_client, admin_session, tenant_a):
    """Logout must mark the AuthSession revoked; replaying the old cookie is rejected."""
    from app.models.auth import UserCredential
    from app.models.person import Person
    from app.services.security import hash_password

    p = Person(tenant_id=tenant_a.id, email="x@alpha.edu", first_name="X", last_name="Y")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=p.id,
            email="x@alpha.edu",
            password_hash=hash_password("pw1234"),
        )
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}

    # Obtain csrf_token.
    r = app_client.get("/login", headers=h, follow_redirects=False)
    csrf = r.cookies.get("csrf_token") or app_client.cookies.get("csrf_token", "")

    # Login — captures session cookie.
    r = app_client.post(
        "/login",
        headers={**h, "x-csrf-token": csrf},
        data={"email": "x@alpha.edu", "password": "pw1234"},
        follow_redirects=False,
    )
    assert r.status_code == 303 and "session" in r.cookies
    old_session_token = r.cookies["session"]

    # Logout.
    r = app_client.post(
        "/logout",
        headers={**h, "x-csrf-token": csrf},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)

    # Re-issue GET /account with the OLD session cookie — must redirect (session revoked).
    app_client.cookies.set("session", old_session_token)
    r = app_client.get(
        "/account",
        headers={**h},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303), "Revoked session must not authenticate"


def test_cross_tenant_cookie_rejected(app_client, admin_session, tenant_a, tenant_b):
    """A session cookie minted for tenant_a must not authenticate on tenant_b."""
    from app.models.auth import UserCredential
    from app.models.person import Person
    from app.services.security import hash_password

    p = Person(tenant_id=tenant_a.id, email="q@alpha.edu", first_name="Q", last_name="Z")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=p.id,
            email="q@alpha.edu",
            password_hash=hash_password("pw5678"),
        )
    )
    admin_session.commit()

    h_a = {"Host": "alpha.localhost"}

    # Obtain csrf_token from tenant_a login page.
    r = app_client.get("/login", headers=h_a, follow_redirects=False)
    csrf = r.cookies.get("csrf_token") or app_client.cookies.get("csrf_token", "")

    # Login on tenant_a — capture session cookie.
    r = app_client.post(
        "/login",
        headers={**h_a, "x-csrf-token": csrf},
        data={"email": "q@alpha.edu", "password": "pw5678"},
        follow_redirects=False,
    )
    assert r.status_code == 303 and "session" in r.cookies
    session_token = r.cookies["session"]

    # Present that session cookie against tenant_b — must be rejected.
    h_b = {"Host": "beta.localhost"}
    replay = TestClient(app_client.app)
    replay.cookies.set("session", session_token)
    r = replay.get(
        "/account",
        headers=h_b,
        follow_redirects=False,
    )
    assert r.status_code in (302, 303), "Cross-tenant session must not authenticate"
