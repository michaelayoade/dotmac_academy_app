"""Tests for the admin applications page."""

from __future__ import annotations

from datetime import date

from app.models.auth import UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole
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
