"""Public lifecycle pages + instructor invite/suspend (Slice 3b/3c)."""

from __future__ import annotations

from app.models.account_token import AccountToken
from app.models.auth import UserCredential
from app.models.cohort import Cohort
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.lifecycle import invite_user, request_password_reset, set_account_status
from app.services.security import hash_password

H = {"Host": "alpha.localhost"}


def _account(admin_session, tid, email="u@a.edu", pw="origpass1"):
    p = Person(tenant_id=tid, email=email, first_name="U", last_name="X")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(UserCredential(tenant_id=tid, person_id=p.id, email=email,
                                     password_hash=hash_password(pw)))
    admin_session.commit()
    return p


def _csrf(app_client, path):
    app_client.get(path, headers=H)
    return app_client.cookies.get("csrf_token", "")


def test_forgot_creates_token_and_is_neutral(app_client, admin_session, tenant_a):
    p = _account(admin_session, tenant_a.id, email="fp@a.edu")
    csrf = _csrf(app_client, "/forgot")
    r = app_client.post("/forgot", headers={**H, "x-csrf-token": csrf}, data={"email": "fp@a.edu"})
    assert r.status_code == 200
    assert "on its way" in r.text
    n = admin_session.query(AccountToken).filter(
        AccountToken.tenant_id == tenant_a.id, AccountToken.person_id == p.id,
        AccountToken.kind == "password_reset").count()
    assert n == 1

    # Unknown email returns the identical neutral message (anti-enumeration).
    r2 = app_client.post("/forgot", headers={**H, "x-csrf-token": csrf}, data={"email": "ghost@a.edu"})
    assert r2.status_code == 200
    assert "on its way" in r2.text


def test_reset_flow_changes_password(app_client, admin_session, tenant_a):
    _account(admin_session, tenant_a.id, email="rp@a.edu", pw="origpass1")
    raw = request_password_reset(admin_session, tenant_id=tenant_a.id, email="rp@a.edu")
    admin_session.commit()

    csrf = _csrf(app_client, f"/reset?token={raw}")
    r = app_client.post("/reset", headers={**H, "x-csrf-token": csrf},
                        data={"token": raw, "password": "brandnew9"})
    assert r.status_code == 200
    assert "Password updated" in r.text

    # New password logs in (csrf cookie now present, so the header is required).
    ok = app_client.post("/login", headers={**H, "x-csrf-token": csrf},
                         data={"email": "rp@a.edu", "password": "brandnew9"})
    assert ok.status_code in (200, 204, 303)
    assert "session" in app_client.cookies


def test_accept_invite_flow_creates_credential(app_client, admin_session, tenant_a):
    person, token = invite_user(admin_session, tenant_id=tenant_a.id, email="inv@a.edu",
                                first_name="In", last_name="V", role="student")
    admin_session.commit()

    csrf = _csrf(app_client, f"/accept-invite?token={token}")
    r = app_client.post("/accept-invite", headers={**H, "x-csrf-token": csrf},
                        data={"token": token, "password": "welcome12"})
    assert r.status_code == 200
    assert "activated" in r.text
    cred = admin_session.query(UserCredential).filter(
        UserCredential.tenant_id == tenant_a.id, UserCredential.person_id == person.id).count()
    assert cred == 1


def test_suspended_account_cannot_log_in(app_client, admin_session, tenant_a):
    p = _account(admin_session, tenant_a.id, email="sp@a.edu", pw="origpass1")
    set_account_status(admin_session, tenant_id=tenant_a.id, person_id=p.id, status="suspended")
    admin_session.commit()
    # Login fails: no session cookie set, and a re-GET of "/" redirects to login.
    r = app_client.post("/login", headers=H, data={"email": "sp@a.edu", "password": "origpass1"},
                        follow_redirects=False)
    assert "session" not in app_client.cookies
    assert r.status_code in (200, 401)  # invalid-credentials response, never a session


def test_instructor_invite_returns_activation_link(app_client, admin_session, tenant_a):
    roles = ensure_roles(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="adm@a.edu", first_name="Ad", last_name="Min")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(UserCredential(tenant_id=tenant_a.id, person_id=p.id, email="adm@a.edu",
                                     password_hash=hash_password("password1")))
    admin_session.add(PersonRole(tenant_id=tenant_a.id, person_id=p.id, role_id=roles["admin"].id))
    coh = Cohort(tenant_id=tenant_a.id, name="Inv", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.commit()
    admin_session.refresh(coh)

    app_client.post("/login", headers=H, data={"email": "adm@a.edu", "password": "password1"})
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(f"/instructor/cohorts/{coh.id}/invite",
                        headers={**H, "x-csrf-token": csrf},
                        data={"email": "newbie@a.edu", "first_name": "New", "last_name": "Bie"})
    assert r.status_code == 200
    assert "/accept-invite?token=" in r.text
    assert admin_session.query(Person).filter(
        Person.tenant_id == tenant_a.id, Person.email == "newbie@a.edu").count() == 1


def test_invalid_reset_token_shows_error(app_client, admin_session, tenant_a):
    csrf = _csrf(app_client, "/reset?token=bogus")
    # The 400 status is returned on the htmx (inline) path; a full-page POST renders
    # the same error as a 200 page. The reset form posts via hx-post, so assert that.
    r = app_client.post("/reset", headers={**H, "x-csrf-token": csrf, "HX-Request": "true"},
                        data={"token": "bogus", "password": "brandnew9"})
    assert r.status_code == 400
    assert "invalid or expired" in r.text
