"""Public lifecycle pages + instructor invite/suspend (Slice 3b/3c)."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select

from app.models.account_token import AccountToken
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.email_outbox import EmailOutbox
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.lifecycle import invite_user, request_password_reset, set_account_status
from app.services.security import hash_password
from app.services.settings_store import set_many

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
    assert "Returning to login" in r.text
    assert "window.location.href='/login'" in r.text
    n = admin_session.query(AccountToken).filter(
        AccountToken.tenant_id == tenant_a.id, AccountToken.person_id == p.id,
        AccountToken.kind == "password_reset").count()
    assert n == 1

    # Unknown email returns the identical neutral message (anti-enumeration).
    r2 = app_client.post("/forgot", headers={**H, "x-csrf-token": csrf}, data={"email": "ghost@a.edu"})
    assert r2.status_code == 200
    assert "on its way" in r2.text


def test_forgot_email_uses_stored_smtp_settings(app_client, admin_session, tenant_a, monkeypatch):
    _account(admin_session, tenant_a.id, email="smtp-reset@a.edu")
    set_many(admin_session, {"smtp_host": "smtp.example", "smtp_from": "academy@example.com"})
    admin_session.commit()
    sent = {}

    def _fake_send_email(
        to,
        subject,
        html_body,
        text_body=None,
        db=None,
        attachments=None,
        message_id=None,
    ):
        from app.services.email import EmailResult
        from app.services.settings_store import effective

        cfg = effective(db)
        sent.update(
            to=to,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            smtp_host=cfg.smtp_host,
            smtp_from=cfg.smtp_from,
        )
        return EmailResult(True)

    from app.services import email_outbox as outbox_mod

    monkeypatch.setattr(outbox_mod, "send_email_detailed", _fake_send_email)
    csrf = _csrf(app_client, "/forgot")
    r = app_client.post(
        "/forgot",
        headers={**H, "x-csrf-token": csrf},
        data={"email": "smtp-reset@a.edu"},
    )

    assert r.status_code == 200
    admin_session.rollback()
    queued = admin_session.scalars(
        select(EmailOutbox)
        .where(EmailOutbox.tenant_id == tenant_a.id)
        .where(EmailOutbox.kind == "password_reset")
    ).one()
    assert queued.status == "pending"
    assert "http://alpha.localhost/reset?token=" in queued.html_body
    assert "http://alpha.localhost/reset?token=" in queued.text_body

    delivered = outbox_mod.deliver_pending(
        admin_session,
        now=queued.available_at + timedelta(seconds=1),
    )
    admin_session.commit()
    assert delivered["sent"] == 1
    assert sent["to"] == "smtp-reset@a.edu"
    assert sent["smtp_host"] == "smtp.example"
    assert sent["smtp_from"] == "academy@example.com"
    assert "http://alpha.localhost/reset?token=" in sent["html_body"]
    assert "http://alpha.localhost/reset?token=" in sent["text_body"]


def test_reset_flow_changes_password(app_client, admin_session, tenant_a):
    email = f"rp-{uuid4().hex}@a.edu"
    old_password = f"old-{uuid4().hex}"
    new_password = f"new-{uuid4().hex}"
    _account(admin_session, tenant_a.id, email=email, pw=old_password)
    raw = request_password_reset(admin_session, tenant_id=tenant_a.id, email=email)
    admin_session.commit()

    csrf = _csrf(app_client, f"/reset?token={raw}")
    r = app_client.post("/reset", headers={**H, "x-csrf-token": csrf},
                        data={"token": raw, "password": new_password})
    assert r.status_code == 200
    assert "Password updated" in r.text

    old = app_client.post("/login", headers={**H, "x-csrf-token": csrf},
                          data={"email": email, "password": old_password})
    assert old.status_code in (200, 401)
    assert "session" not in app_client.cookies

    # New password logs in (csrf cookie now present, so the header is required).
    ok = app_client.post("/login", headers={**H, "x-csrf-token": csrf},
                         data={"email": email, "password": new_password})
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


def test_instructor_invite_queues_activation_link_without_exposing_token(
    app_client,
    admin_session,
    tenant_a,
    monkeypatch,
):
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
    assert "Invite email queued" in r.text
    assert "/accept-invite?token=" not in r.text
    admin_session.rollback()
    queued = admin_session.scalars(
        select(EmailOutbox)
        .where(EmailOutbox.tenant_id == tenant_a.id)
        .where(EmailOutbox.kind == "account_invite")
    ).one()
    assert queued.recipient == "newbie@a.edu"
    assert "/accept-invite?token=" in queued.html_body
    assert admin_session.query(Person).filter(
        Person.tenant_id == tenant_a.id, Person.email == "newbie@a.edu").count() == 1

    delivered_to = []

    def _deliver(to, *args, **kwargs):
        from app.services.email import EmailResult

        delivered_to.append(to)
        return EmailResult(True)

    from app.services import email_outbox

    monkeypatch.setattr(email_outbox, "send_email_detailed", _deliver)
    result = email_outbox.deliver_pending(
        admin_session,
        now=queued.available_at + timedelta(seconds=1),
    )
    assert result == {"sent": 1, "retried": 0, "failed": 0}
    assert delivered_to == ["newbie@a.edu"]


def test_duplicate_cohort_invite_reuses_person_and_enrollment(
    app_client,
    admin_session,
    tenant_a,
):
    roles = ensure_roles(admin_session, tenant_a.id)
    admin = Person(tenant_id=tenant_a.id, email="duplicate-admin@a.edu", first_name="Ad", last_name="Min")
    cohort = Cohort(tenant_id=tenant_a.id, name="Duplicate Invites", discipline="networking", status="active")
    admin_session.add_all([admin, cohort])
    admin_session.flush()
    admin_session.add_all(
        [
            UserCredential(
                tenant_id=tenant_a.id,
                person_id=admin.id,
                email=admin.email,
                password_hash=hash_password("password1"),
            ),
            PersonRole(tenant_id=tenant_a.id, person_id=admin.id, role_id=roles["admin"].id),
        ]
    )
    admin_session.commit()

    app_client.post("/login", headers=H, data={"email": admin.email, "password": "password1"})
    csrf = app_client.cookies.get("csrf_token", "")
    url = f"/instructor/cohorts/{cohort.id}/invite"
    data = {"email": " Repeat.Student@a.edu ", "first_name": "Repeat", "last_name": "Student"}
    first = app_client.post(url, headers={**H, "x-csrf-token": csrf}, data=data)
    second = app_client.post(url, headers={**H, "x-csrf-token": csrf}, data=data)

    assert first.status_code == 200
    assert second.status_code == 200
    admin_session.rollback()
    students = admin_session.scalars(
        select(Person).where(Person.tenant_id == tenant_a.id).where(Person.email == "repeat.student@a.edu")
    ).all()
    assert len(students) == 1
    assert (
        admin_session.query(Enrollment)
        .filter(
            Enrollment.tenant_id == tenant_a.id,
            Enrollment.cohort_id == cohort.id,
            Enrollment.person_id == students[0].id,
        )
        .count()
        == 1
    )
    tokens = admin_session.scalars(
        select(AccountToken)
        .where(AccountToken.tenant_id == tenant_a.id)
        .where(AccountToken.person_id == students[0].id)
        .where(AccountToken.kind == "invite")
    ).all()
    assert len(tokens) == 2
    assert sum(token.used_at is None for token in tokens) == 1


def test_cohort_invite_enrolls_existing_login_without_activation_email(
    app_client,
    admin_session,
    tenant_a,
):
    roles = ensure_roles(admin_session, tenant_a.id)
    admin = Person(tenant_id=tenant_a.id, email="existing-admin@a.edu", first_name="Ad", last_name="Min")
    student = Person(tenant_id=tenant_a.id, email="existing-student@a.edu", first_name="Existing", last_name="Student")
    cohort = Cohort(tenant_id=tenant_a.id, name="Existing Users", discipline="networking", status="active")
    admin_session.add_all([admin, student, cohort])
    admin_session.flush()
    admin_session.add_all(
        [
            UserCredential(
                tenant_id=tenant_a.id,
                person_id=admin.id,
                email=admin.email,
                password_hash=hash_password("password1"),
            ),
            UserCredential(
                tenant_id=tenant_a.id,
                person_id=student.id,
                email=student.email,
                password_hash=hash_password("password1"),
            ),
            PersonRole(tenant_id=tenant_a.id, person_id=admin.id, role_id=roles["admin"].id),
        ]
    )
    admin_session.commit()

    app_client.post("/login", headers=H, data={"email": admin.email, "password": "password1"})
    csrf = app_client.cookies.get("csrf_token", "")
    response = app_client.post(
        f"/instructor/cohorts/{cohort.id}/invite",
        headers={**H, "x-csrf-token": csrf},
        data={"email": " EXISTING-STUDENT@a.edu ", "first_name": "Existing", "last_name": "Student"},
    )

    assert response.status_code == 200
    assert "Existing account can sign in" in response.text
    admin_session.rollback()
    assert (
        admin_session.query(Enrollment)
        .filter(
            Enrollment.tenant_id == tenant_a.id,
            Enrollment.cohort_id == cohort.id,
            Enrollment.person_id == student.id,
        )
        .count()
        == 1
    )
    assert (
        admin_session.query(EmailOutbox)
        .filter(
            EmailOutbox.tenant_id == tenant_a.id,
            EmailOutbox.kind == "account_invite",
            EmailOutbox.recipient == student.email,
        )
        .count()
        == 0
    )


def test_invalid_reset_token_shows_error(app_client, admin_session, tenant_a):
    csrf = _csrf(app_client, "/reset?token=bogus")
    # The 400 status is returned on the htmx (inline) path; a full-page POST renders
    # the same error as a 200 page. The reset form posts via hx-post, so assert that.
    r = app_client.post("/reset", headers={**H, "x-csrf-token": csrf, "HX-Request": "true"},
                        data={"token": "bogus", "password": "brandnew9"})
    assert r.status_code == 400
    assert "invalid or expired" in r.text
