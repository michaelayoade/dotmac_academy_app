"""Tests for the Account area — profile + password change (Task 7)."""

from __future__ import annotations

from app.models.auth import UserCredential
from app.models.person import Person
from app.services.security import hash_password


def _login(app_client, admin_session, tenant, password="password1"):
    p = Person(tenant_id=tenant.id, email="s@a.edu", first_name="S", last_name="L")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email="s@a.edu",
            password_hash=hash_password(password),
        )
    )
    admin_session.commit()
    h = {"Host": "alpha.localhost"}
    # First request has no cookies → CSRF middleware skips (empty cookie jar).
    app_client.post("/login", headers=h, data={"email": "s@a.edu", "password": password})
    csrf = app_client.cookies.get("csrf_token", "")
    return p, h, csrf


def _can_login(app_client, h, csrf, password):
    """Drive /login and report whether the credentials are accepted."""
    r = app_client.post(
        "/login",
        headers={**h, "x-csrf-token": csrf},
        data={"email": "s@a.edu", "password": password},
        follow_redirects=False,
    )
    return r.status_code == 303


def test_profile_update_changes_name(app_client, admin_session, tenant_a):
    _p, h, csrf = _login(app_client, admin_session, tenant_a)

    r = app_client.post(
        "/account",
        headers={**h, "x-csrf-token": csrf},
        data={"first_name": "Newfirst", "last_name": "Newlast"},
    )
    assert r.status_code == 200

    r = app_client.get("/account", headers=h)
    assert r.status_code == 200
    assert "Newfirst" in r.text
    assert "Newlast" in r.text
    # Email is read-only / unchanged.
    assert "s@a.edu" in r.text


def test_password_wrong_current_rejected(app_client, admin_session, tenant_a):
    _p, h, csrf = _login(app_client, admin_session, tenant_a)

    r = app_client.post(
        "/account/password",
        headers={**h, "x-csrf-token": csrf},
        data={
            "current_password": "wrongpass",
            "new_password": "brandnew2",
            "confirm_password": "brandnew2",
        },
    )
    assert r.status_code == 200
    assert "error" in r.text.lower() or "incorrect" in r.text.lower()

    # Old password still works; the new one was NOT applied.
    assert _can_login(app_client, h, csrf, "password1") is True
    assert _can_login(app_client, h, csrf, "brandnew2") is False


def test_password_change_success(app_client, admin_session, tenant_a):
    _p, h, csrf = _login(app_client, admin_session, tenant_a)

    r = app_client.post(
        "/account/password",
        headers={**h, "x-csrf-token": csrf},
        data={
            "current_password": "password1",
            "new_password": "brandnew2",
            "confirm_password": "brandnew2",
        },
    )
    assert r.status_code == 200
    assert "updated" in r.text.lower() or "success" in r.text.lower()

    # New password works; old does not.
    assert _can_login(app_client, h, csrf, "brandnew2") is True
    assert _can_login(app_client, h, csrf, "password1") is False


def test_password_mismatch_or_short_rejected(app_client, admin_session, tenant_a):
    _p, h, csrf = _login(app_client, admin_session, tenant_a)

    # Too short.
    r = app_client.post(
        "/account/password",
        headers={**h, "x-csrf-token": csrf},
        data={"current_password": "password1", "new_password": "short", "confirm_password": "short"},
    )
    assert r.status_code == 200
    assert "error" in r.text.lower() or "least 8" in r.text.lower()

    # Mismatch.
    r = app_client.post(
        "/account/password",
        headers={**h, "x-csrf-token": csrf},
        data={
            "current_password": "password1",
            "new_password": "brandnew2",
            "confirm_password": "different2",
        },
    )
    assert r.status_code == 200
    assert "error" in r.text.lower() or "match" in r.text.lower()

    # Password unchanged — original still logs in.
    assert _can_login(app_client, h, csrf, "password1") is True
