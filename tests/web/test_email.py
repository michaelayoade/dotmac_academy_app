"""Tests for the on-demand email routes in the instructor Reports portal."""

from __future__ import annotations

from app.models.assessment import Activity, Score, Submission
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.bootstrap import ensure_roles
from app.services.security import hash_password


def _seed_login(admin_session, tenant, email, role_slug):
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email=email, first_name="Log", last_name="In")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(UserCredential(tenant_id=tenant.id, person_id=p.id, email=email,
                                     password_hash=hash_password("password1")))
    admin_session.add(PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles[role_slug].id))
    admin_session.commit()
    return p


def _seed_cohort(admin_session, tid):
    c = Course(tenant_id=tid, slug="net", title="Networking", discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    a1 = Activity(tenant_id=tid, course_id=c.id, chapter_number=1, type="mcq_test",
                  title="Ch1 Test", pass_threshold=0.6)
    admin_session.add(a1)
    admin_session.flush()
    coh = Cohort(tenant_id=tid, name="Abuja 2026", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    stu_a = Person(tenant_id=tid, email="a@stu.edu", first_name="Aaa", last_name="Student")
    admin_session.add(stu_a)
    admin_session.flush()
    admin_session.add(Enrollment(tenant_id=tid, cohort_id=coh.id, person_id=stu_a.id,
                                 role_in_cohort="student", status="active"))
    sub = Submission(tenant_id=tid, activity_id=a1.id, person_id=stu_a.id, answers={}, attempt_no=1)
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tid, submission_id=sub.id, score=10, max_score=10,
                            fraction=1.0, passed=True, per_item=[], source="auto"))
    admin_session.commit()
    return coh, stu_a


def _login(app_client, email):
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h


def test_student_forbidden_on_email_route(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "stud@a.edu", "student")
    coh, stu_a = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "stud@a.edu")
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/reports/student/{stu_a.id}/email",
        headers={**h, "x-csrf-token": csrf},
    )
    assert r.status_code == 403


def test_instructor_email_student_invokes_send(app_client, admin_session, tenant_a, monkeypatch):
    calls = []
    import app.web.reports as reports_web
    monkeypatch.setattr(reports_web, "send_email",
                        lambda to, subject, html, text_body=None: calls.append(to) or True)

    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh, stu_a = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "inst@a.edu")
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/reports/student/{stu_a.id}/email",
        headers={**h, "x-csrf-token": csrf},
    )
    assert r.status_code == 200
    assert calls == ["a@stu.edu"]
    assert "Email sent" in r.text


def test_instructor_email_cohort_to_self(app_client, admin_session, tenant_a, monkeypatch):
    calls = []
    import app.web.reports as reports_web
    monkeypatch.setattr(reports_web, "send_email",
                        lambda to, subject, html, text_body=None: calls.append(to) or True)

    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh, _ = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "inst@a.edu")
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/reports/cohort/{coh.id}/email",
        headers={**h, "x-csrf-token": csrf},
    )
    assert r.status_code == 200
    assert calls == ["inst@a.edu"]
