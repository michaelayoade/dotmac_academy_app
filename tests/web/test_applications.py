"""Tests for the admin applications page."""

from __future__ import annotations

import csv
import io
from datetime import date, datetime

from sqlalchemy import select

from app.models.auth import UserCredential
from app.models.cohort import Cohort
from app.models.email_outbox import EmailOutbox
from app.models.person import Person
from app.models.rbac import AuditEvent, PersonRole
from app.models.track import CohortTrack, Track
from app.services import admissions
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _seed_user(admin_session, tenant, email, role_slug):
    roles = ensure_roles(admin_session, tenant.id)
    person = Person(tenant_id=tenant.id, email=email, first_name="Seed", last_name="User")
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
    admin_session.add(PersonRole(tenant_id=tenant.id, person_id=person.id, role_id=roles[role_slug].id))
    admin_session.commit()
    return person


def _login(app_client, email):
    headers = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=headers, data={"email": email, "password": "password1"})
    return headers


def _intake(admin_session, tenant):
    cohort = Cohort(
        tenant_id=tenant.id,
        name="Abuja Intake",
        discipline="fiber",
        status="active",
    )
    track = Track(
        tenant_id=tenant.id,
        slug="fiber-installer",
        name="Fiber Installer",
        status="active",
    )
    admin_session.add_all([cohort, track])
    admin_session.flush()
    admin_session.add(
        CohortTrack(
            tenant_id=tenant.id,
            cohort_id=cohort.id,
            track_id=track.id,
            status="active",
        )
    )
    admin_session.commit()
    return cohort, track


def test_admin_can_view_applications_page(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "apps-admin@a.edu", "admin")
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="candidate@a.edu",
        first_name="Candidate",
        last_name="One",
        phone="08000000000",
        program="Fiber Academy",
    )
    admin_session.commit()

    response = app_client.get("/admin/applications", headers=_login(app_client, "apps-admin@a.edu"))

    assert response.status_code == 200
    assert "Applications" in response.text
    assert "candidate@a.edu" in response.text
    assert "Applicant pipeline" in response.text


def test_admin_can_search_applications_by_applicant_name(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "apps-search-admin@a.edu", "admin")
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="amina@a.edu",
        first_name="Amina",
        last_name="Yusuf",
    )
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="bala@a.edu",
        first_name="Bala",
        last_name="Okoro",
    )
    admin_session.commit()

    response = app_client.get(
        "/admin/applications?q=amina",
        headers=_login(app_client, "apps-search-admin@a.edu"),
    )

    assert response.status_code == 200
    assert "amina@a.edu" in response.text
    assert "bala@a.edu" not in response.text
    assert 'value="amina"' in response.text
    assert 'href="/admin/applications/export.csv?q=amina"' in response.text


def test_admin_can_filter_applications_by_applied_date_range(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "apps-date-admin@a.edu", "admin")
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="early@a.edu",
        first_name="Early",
        last_name="Applicant",
        applied_on=date(2026, 1, 10),
    )
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="inside@a.edu",
        first_name="Inside",
        last_name="Applicant",
        applied_on=date(2026, 2, 15),
    )
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="late@a.edu",
        first_name="Late",
        last_name="Applicant",
        applied_on=date(2026, 3, 10),
    )
    admin_session.commit()

    response = app_client.get(
        "/admin/applications?applied_from=2026-02-01&applied_to=2026-02-28",
        headers=_login(app_client, "apps-date-admin@a.edu"),
    )

    assert response.status_code == 200
    assert "inside@a.edu" in response.text
    assert "early@a.edu" not in response.text
    assert "late@a.edu" not in response.text
    assert 'value="2026-02-01"' in response.text
    assert 'value="2026-02-28"' in response.text


def test_admin_can_export_filtered_applications_csv(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "apps-export-admin@a.edu", "admin")
    exported = admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="amina-export@a.edu",
        first_name="Amina",
        last_name="Yusuf",
        phone="08011111111",
        program="Fiber Academy",
        applied_on=date(2026, 2, 15),
        profile={
            "state": "FCT",
            "city": "Abuja",
            "highest_qualification": "OND",
            "years_experience": 2,
            "has_device": True,
            "has_internet": False,
            "available_from": date(2026, 3, 1),
            "heard_from": "Referral",
            "cv_url": "=https://example.test/cv.csv",
        },
    )
    exported.assessment_score = 0.82
    exported.assessment_level = "ready"
    exported.assessment_taken_at = datetime(2026, 2, 15, 9, 30, 45)
    exported.assessment_valid = False
    exported.assessment_invalid_reason = "too_fast"
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="bala-export@a.edu",
        first_name="Bala",
        last_name="Okoro",
        applied_on=date(2026, 2, 16),
    )
    admin_session.commit()

    response = app_client.get(
        "/admin/applications/export.csv?q=amina",
        headers=_login(app_client, "apps-export-admin@a.edu"),
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers.get("content-disposition", "")
    assert "applicants_export_" in disposition
    assert disposition.endswith('.csv"')

    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "Amina Yusuf"
    assert row["email"] == "amina-export@a.edu"
    assert row["phone"] == "08011111111"
    assert row["program"] == "Fiber Academy"
    assert row["status"] == "applied"
    assert row["applied_on"] == "2026-02-15"
    assert row["assessment_score_pct"] == "82"
    assert row["assessment_level"] == "ready"
    assert row["assessment_taken_at"] == "2026-02-15T09:30:45"
    assert row["assessment_valid"] == "false"
    assert row["assessment_invalid_reason"] == "too_fast"
    assert row["profile_complete"] == "false"
    assert row["missing_profile_fields"] == "date_of_birth"
    assert row["state"] == "FCT"
    assert row["city"] == "Abuja"
    assert row["highest_qualification"] == "OND"
    assert row["years_experience"] == "2"
    assert row["has_device"] == "true"
    assert row["has_internet"] == "false"
    assert row["available_from"] == "2026-03-01"
    assert row["heard_from"] == "Referral"
    assert row["cv_url"] == "'=https://example.test/cv.csv"


def test_reversed_application_date_range_shows_validation_message(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "apps-reversed-date-admin@a.edu", "admin")
    admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="candidate-reversed@a.edu",
        first_name="Range",
        last_name="Candidate",
        applied_on=date(2026, 7, 28),
    )
    admin_session.commit()

    response = app_client.get(
        "/admin/applications?applied_from=2026-07-28&applied_to=2026-07-27",
        headers=_login(app_client, "apps-reversed-date-admin@a.edu"),
    )

    assert response.status_code == 200
    assert "Start date must be before or the same as end date." in response.text
    assert "candidate-reversed@a.edu" not in response.text
    assert 'value="2026-07-28"' in response.text
    assert 'value="2026-07-27"' in response.text


def test_student_cannot_view_applications_page(app_client, admin_session, tenant_a):
    _seed_user(admin_session, tenant_a, "apps-student@a.edu", "student")

    response = app_client.get("/admin/applications", headers=_login(app_client, "apps-student@a.edu"))

    assert response.status_code == 403


def test_admin_assigns_canonical_intake_then_accepts_with_audited_history(
    app_client,
    admin_session,
    tenant_a,
):
    actor = _seed_user(admin_session, tenant_a, "review-admin@a.edu", "admin")
    cohort, track = _intake(admin_session, tenant_a)
    applicant = admissions.submit_application(
        admin_session,
        tenant_id=tenant_a.id,
        email="legacy-candidate@a.edu",
        first_name="Legacy",
        last_name="Candidate",
    )
    admin_session.commit()
    applicant_id = applicant.id

    headers = _login(app_client, "review-admin@a.edu")
    detail = app_client.get(
        f"/admin/applications/{applicant_id}",
        headers=headers,
    )
    assert detail.status_code == 200
    assert "Training placement" in detail.text
    assert "Accept and invite to onboarding" not in detail.text

    csrf = app_client.cookies.get("csrf_token", "")
    assigned = app_client.post(
        f"/admin/applications/{applicant_id}/intake",
        headers={**headers, "x-csrf-token": csrf},
        data={
            "intake_choice": f"{cohort.id}:{track.id}",
            "reason": "Mapped legacy application",
        },
        follow_redirects=False,
    )
    assert assigned.status_code == 303

    accepted = app_client.post(
        f"/admin/applications/{applicant_id}/action",
        headers={**headers, "x-csrf-token": csrf},
        data={"action": "accept", "reason": "Assessment reviewed"},
        follow_redirects=False,
    )
    assert accepted.status_code == 303
    assert "token=" not in accepted.text

    admin_session.rollback()
    admin_session.refresh(applicant)
    assert applicant.cohort_id == cohort.id
    assert applicant.track_id == track.id
    assert applicant.program == "Fiber Installer"
    assert applicant.status == "onboarding"

    events = list(
        admin_session.scalars(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_a.id)
            .where(AuditEvent.entity_id == str(applicant_id))
            .order_by(AuditEvent.created_at)
        ).all()
    )
    assert events[0].action == "applicant.intake_assigned"
    assert events[0].actor_person_id == actor.id
    assert events[0].details["reason"] == "Mapped legacy application"
    transitions = [event for event in events if event.action == "applicant.transition"]
    assert [event.details["to_status"] for event in transitions] == [
        "screened",
        "accepted",
        "onboarding",
    ]
    assert all(event.details["source"] == "admin_web" for event in transitions)

    invitation = admin_session.scalars(
        select(EmailOutbox)
        .where(EmailOutbox.tenant_id == tenant_a.id)
        .where(EmailOutbox.kind == "onboarding_invite")
    ).one()
    assert invitation.recipient == applicant.email
