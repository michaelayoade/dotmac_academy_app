"""Self-serve onboarding portal — tokenized checklist → automatic enrolment.

Requires a migrated disposable Postgres (skipped otherwise by the fixtures).
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.conftest import client_for

_PW = "correct horse battery staple"


def _admin(client, slug):
    c = client_for(client, slug)
    c.post(
        "/auth/register",
        json={"email": f"adm@{slug}.ex", "password": _PW, "first_name": "Ad", "last_name": "Min"},
    )
    tok = c.post("/auth/login", json={"email": f"adm@{slug}.ex", "password": _PW}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def _cohort(admin_session, tenant, name="Fiber intake"):
    from app.models.cohort import Cohort

    admin_session.rollback()
    c = Cohort(tenant_id=tenant.id, name=name, discipline="fiber", status="active")
    admin_session.add(c)
    admin_session.commit()
    admin_session.refresh(c)
    return c


def _applicant_in_onboarding(client, auth, admin_session, tenant, email):
    """Apply + advance to onboarding via the admin API; return (app_id, portal_token)."""
    cohort = _cohort(admin_session, tenant)
    a = client_for(TestClient(client.app), tenant.slug)
    app_id = a.post(
        "/admissions/apply",
        json={"email": email, "first_name": "On", "last_name": "Boarder"},
    ).json()["id"]
    # Attach the cohort so auto-enrol knows the target.
    admin_session.rollback()
    admin_session.execute(
        text("UPDATE applicants SET cohort_id=:c WHERE id=:a"),
        {"c": str(cohort.id), "a": app_id},
    )
    admin_session.commit()
    for nxt in ("screened", "accepted", "onboarding"):
        r = a.post(f"/admissions/{app_id}/transition", json={"to_status": nxt}, headers=auth)
        assert r.status_code == 200, r.text
    # The transition to onboarding minted the portal token; recover a fresh one
    # the same way the service does (the raw is only ever emailed).
    from uuid import UUID

    from app.models.admissions import Applicant
    from app.services import admissions as admissions_service

    admin_session.rollback()
    applicant = admin_session.get(Applicant, UUID(app_id))
    raw = admissions_service.mint_onboarding_token(admin_session, applicant=applicant)
    admin_session.commit()
    return app_id, raw


def test_portal_requires_valid_token(app_client, tenant_a):
    a = client_for(app_client, tenant_a.slug)
    r = a.get("/onboarding?token=not-a-token")
    assert r.status_code == 200
    assert "Link not valid" in r.text


def test_transition_to_onboarding_mints_portal_token(app_client, tenant_a, admin_session):
    auth = _admin(app_client, tenant_a.slug)
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    app_id = a.post(
        "/admissions/apply",
        json={"email": "mint@a.ex", "first_name": "Mi", "last_name": "Nt"},
    ).json()["id"]
    for nxt in ("screened", "accepted", "onboarding"):
        a.post(f"/admissions/{app_id}/transition", json={"to_status": nxt}, headers=auth)
    admin_session.rollback()
    got = admin_session.execute(
        text("SELECT onboarding_token_hash FROM applicants WHERE id=:a"), {"a": app_id}
    ).scalar()
    assert got  # minted on entering onboarding


def test_portal_renders_checklist(app_client, tenant_a, admin_session):
    auth = _admin(app_client, tenant_a.slug)
    app_id, token = _applicant_in_onboarding(app_client, auth, admin_session, tenant_a, "check@a.ex")
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    r = a.get(f"/onboarding?token={token}")
    assert r.status_code == 200
    assert "Confirm your details" in r.text
    assert "Programme orientation" in r.text
    assert "check@a.ex" in r.text


def test_completing_checklist_auto_enrolls_and_invites(app_client, tenant_a, admin_session):
    auth = _admin(app_client, tenant_a.slug)
    app_id, token = _applicant_in_onboarding(app_client, auth, admin_session, tenant_a, "auto@a.ex")
    a = client_for(TestClient(app_client.app), tenant_a.slug)

    # No entrance exam configured for this cohort -> the seeded assessment task
    # still gates enrolment; complete it as the carry-forward would.
    admin_session.rollback()
    admin_session.execute(
        text("UPDATE onboarding_tasks SET status='done' " "WHERE applicant_id=:a AND key='entrance_assessment'"),
        {"a": app_id},
    )
    admin_session.commit()

    r = a.post("/onboarding/confirm", data={"token": token}, follow_redirects=False)
    assert r.status_code == 303
    # Not yet enrolled — orientation still pending.
    admin_session.rollback()
    status = admin_session.execute(text("SELECT status FROM applicants WHERE id=:a"), {"a": app_id}).scalar()
    assert status == "onboarding"

    r = a.post("/onboarding/orientation", data={"token": token}, follow_redirects=False)
    assert r.status_code == 303

    admin_session.rollback()
    row = admin_session.execute(text("SELECT status, person_id FROM applicants WHERE id=:a"), {"a": app_id}).one()
    assert row.status == "enrolled"
    assert row.person_id is not None
    # Enrolment artefacts: enrollment row, student role, and a password invite.
    enr = admin_session.execute(
        text("SELECT count(*) FROM enrollments WHERE person_id=:p"), {"p": str(row.person_id)}
    ).scalar()
    assert enr == 1
    role = admin_session.execute(
        text(
            "SELECT count(*) FROM person_roles pr JOIN roles r ON r.id=pr.role_id "
            "WHERE pr.person_id=:p AND r.slug='student'"
        ),
        {"p": str(row.person_id)},
    ).scalar()
    assert role == 1
    invites = admin_session.execute(
        text("SELECT count(*) FROM account_tokens WHERE person_id=:p AND kind='invite'"),
        {"p": str(row.person_id)},
    ).scalar()
    assert invites == 1

    # Idempotent: re-posting completes nothing twice and never re-invites.
    a.post("/onboarding/orientation", data={"token": token})
    admin_session.rollback()
    invites2 = admin_session.execute(
        text("SELECT count(*) FROM account_tokens WHERE person_id=:p AND kind='invite'"),
        {"p": str(row.person_id)},
    ).scalar()
    assert invites2 == 1

    # The portal now shows the enrolled state.
    r = a.get(f"/onboarding?token={token}")
    assert "enrolled" in r.text.lower()


def test_invite_token_activates_student_login(app_client, tenant_a, admin_session):
    """The set-password link from auto-enrolment actually opens the account."""
    auth = _admin(app_client, tenant_a.slug)
    app_id, token = _applicant_in_onboarding(app_client, auth, admin_session, tenant_a, "login@a.ex")
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    admin_session.rollback()
    admin_session.execute(text("UPDATE onboarding_tasks SET status='done' WHERE applicant_id=:a"), {"a": app_id})
    admin_session.commit()
    # Any completed task POST triggers the auto-enrol check.
    a.post("/onboarding/confirm", data={"token": token})

    admin_session.rollback()
    person_id = admin_session.execute(text("SELECT person_id FROM applicants WHERE id=:a"), {"a": app_id}).scalar()
    # Recover a usable invite the same way lifecycle would issue it: mint another.
    from app.services import lifecycle

    raw = lifecycle.issue_invite_for_person(admin_session, tenant_id=tenant_a.id, person_id=person_id)
    admin_session.commit()

    fresh = client_for(TestClient(app_client.app), tenant_a.slug)
    r = fresh.post("/accept-invite", data={"token": raw, "password": "a fine password"})
    assert r.status_code == 200, r.text
    login = fresh.post("/auth/login", json={"email": "login@a.ex", "password": "a fine password"})
    assert login.status_code == 200, login.text
