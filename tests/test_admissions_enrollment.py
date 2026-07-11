"""Admissions P2 — applicant -> enrolled learner conversion.

Requires a migrated disposable Postgres (skipped otherwise by the fixtures).
"""

from __future__ import annotations

from sqlalchemy import text

from tests.conftest import client_for

_PW = "correct horse battery staple"


def _admin(client, slug):
    c = client_for(client, slug)
    c.post(
        "/auth/register",
        json={"email": f"adm@{slug}.ex", "password": _PW, "first_name": "Ad", "last_name": "Min"},
    )
    tok = c.post("/auth/login", json={"email": f"adm@{slug}.ex", "password": _PW}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def _cohort(admin_session, tenant, name="Fiber intake"):
    from app.models.cohort import Cohort

    admin_session.rollback()
    c = Cohort(tenant_id=tenant.id, name=name, discipline="fiber", status="active")
    admin_session.add(c)
    admin_session.commit()
    admin_session.refresh(c)
    return c


def _clear_onboarding(client, auth, app_id):
    """Mark every onboarding task done via the API.

    The GET sets a csrf_token cookie; once cookies exist the CSRF middleware
    enforces the double-submit on POSTs, so we echo the token. Clearing cookies
    afterwards keeps the rest of the (Bearer-auth) API flow cookie-free.
    """
    tasks = client.get(f"/admissions/{app_id}/onboarding", headers=auth).json()
    csrf = client.cookies.get("csrf_token", "")
    for t in tasks:
        client.post(
            f"/admissions/onboarding-tasks/{t['id']}",
            json={"status": "done"},
            headers={**auth, "x-csrf-token": csrf},
        )
    client.cookies.clear()


def _to_onboarding(client, auth, app_id):
    for nxt in ("screened", "accepted", "onboarding"):
        client.post(f"/admissions/{app_id}/transition", json={"to_status": nxt}, headers=auth)
    _clear_onboarding(client, auth, app_id)


def test_enroll_creates_person_and_enrollment(app_client, tenant_a, admin_session):
    a = client_for(app_client, tenant_a.slug)
    auth = _admin(app_client, tenant_a.slug)
    cohort = _cohort(admin_session, tenant_a)
    app_id = a.post(
        "/admissions/apply", json={"email": "learn@a.ex", "first_name": "Lea", "last_name": "Rn"}
    ).json()["id"]
    _to_onboarding(a, auth, app_id)

    r = a.post(f"/admissions/{app_id}/enroll", json={"cohort_id": str(cohort.id)}, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "enrolled"
    assert body["person_id"] is not None

    # A Person + Enrollment now exist for this email/cohort.
    admin_session.rollback()
    pid = admin_session.execute(text("SELECT id FROM people WHERE email='learn@a.ex'")).scalar()
    assert pid is not None
    n = admin_session.execute(
        text("SELECT count(*) FROM enrollments WHERE person_id=:p AND cohort_id=:c"),
        {"p": pid, "c": str(cohort.id)},
    ).scalar()
    assert n == 1


def test_enroll_is_idempotent(app_client, tenant_a, admin_session):
    a = client_for(app_client, tenant_a.slug)
    auth = _admin(app_client, tenant_a.slug)
    cohort = _cohort(admin_session, tenant_a)
    app_id = a.post(
        "/admissions/apply", json={"email": "idem@a.ex", "first_name": "I", "last_name": "D"}
    ).json()["id"]
    _to_onboarding(a, auth, app_id)

    first = a.post(f"/admissions/{app_id}/enroll", json={"cohort_id": str(cohort.id)}, headers=auth)
    # Re-enrol (applicant already 'enrolled') is rejected by the status guard...
    again = a.post(f"/admissions/{app_id}/enroll", json={"cohort_id": str(cohort.id)}, headers=auth)
    assert first.status_code == 200
    assert again.status_code == 400  # not in 'onboarding' anymore

    admin_session.rollback()
    n = admin_session.execute(
        text("SELECT count(*) FROM enrollments WHERE cohort_id=:c"),
        {"c": str(cohort.id)},
    ).scalar()
    assert n == 1  # no duplicate enrolment


def test_enroll_requires_onboarding_status(app_client, tenant_a, admin_session):
    a = client_for(app_client, tenant_a.slug)
    auth = _admin(app_client, tenant_a.slug)
    cohort = _cohort(admin_session, tenant_a)
    app_id = a.post(
        "/admissions/apply", json={"email": "early@a.ex", "first_name": "E", "last_name": "A"}
    ).json()["id"]
    # still 'applied' — enrol must fail
    r = a.post(f"/admissions/{app_id}/enroll", json={"cohort_id": str(cohort.id)}, headers=auth)
    assert r.status_code == 400


def test_enroll_blocked_by_incomplete_onboarding(app_client, tenant_a, admin_session):
    a = client_for(app_client, tenant_a.slug)
    auth = _admin(app_client, tenant_a.slug)
    cohort = _cohort(admin_session, tenant_a)
    app_id = a.post(
        "/admissions/apply", json={"email": "wip@a.ex", "first_name": "W", "last_name": "P"}
    ).json()["id"]
    # Reach onboarding but leave the checklist unfinished.
    for nxt in ("screened", "accepted", "onboarding"):
        a.post(f"/admissions/{app_id}/transition", json={"to_status": nxt}, headers=auth)
    tasks = a.get(f"/admissions/{app_id}/onboarding", headers=auth).json()
    assert len(tasks) >= 1 and all(t["status"] == "pending" for t in tasks)
    a.cookies.clear()  # keep the enrol POST cookie-free (Bearer API, no CSRF)
    r = a.post(f"/admissions/{app_id}/enroll", json={"cohort_id": str(cohort.id)}, headers=auth)
    assert r.status_code == 400  # outstanding onboarding tasks


def test_enroll_reuses_existing_person(app_client, tenant_a, admin_session):
    """An email that is already a Person (e.g. an employee) is reused, not duplicated."""
    from app.models.person import Person

    a = client_for(app_client, tenant_a.slug)
    auth = _admin(app_client, tenant_a.slug)
    cohort = _cohort(admin_session, tenant_a)

    admin_session.rollback()
    existing = Person(
        tenant_id=tenant_a.id, email="staff@a.ex", first_name="Staff", last_name="Member"
    )
    admin_session.add(existing)
    admin_session.commit()
    admin_session.refresh(existing)

    app_id = a.post(
        "/admissions/apply",
        json={"email": "staff@a.ex", "first_name": "Staff", "last_name": "Member"},
    ).json()["id"]
    _to_onboarding(a, auth, app_id)
    r = a.post(f"/admissions/{app_id}/enroll", json={"cohort_id": str(cohort.id)}, headers=auth)
    assert r.status_code == 200
    assert r.json()["person_id"] == str(existing.id)

    admin_session.rollback()
    n = admin_session.execute(text("SELECT count(*) FROM people WHERE email='staff@a.ex'")).scalar()
    assert n == 1  # not duplicated
