"""Tests for the instructor/admin Reports web routes."""

from __future__ import annotations

from app.models.assessment import Activity, Score, Submission
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
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
    a2 = Activity(tenant_id=tid, course_id=c.id, chapter_number=2, type="lab",
                  title="Ch2 Lab", pass_threshold=0.6)
    admin_session.add_all([a1, a2])
    admin_session.flush()
    coh = Cohort(tenant_id=tid, name="Abuja 2026", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(CourseOffering(tenant_id=tid, cohort_id=coh.id, course_id=c.id, status="active"))
    stu_a = Person(tenant_id=tid, email="a@stu.edu", first_name="Aaa", last_name="Student")
    stu_b = Person(tenant_id=tid, email="b@stu.edu", first_name="Bbb", last_name="Student")
    admin_session.add_all([stu_a, stu_b])
    admin_session.flush()
    for p in (stu_a, stu_b):
        admin_session.add(Enrollment(tenant_id=tid, cohort_id=coh.id, person_id=p.id,
                                     role_in_cohort="student", status="active"))
    admin_session.flush()
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


def test_student_forbidden_on_reports(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "stud@a.edu", "student")
    h = _login(app_client, "stud@a.edu")
    assert app_client.get("/instructor/reports", headers=h).status_code == 403


def test_instructor_reports_index(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh, _ = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "inst@a.edu")
    r = app_client.get("/instructor/reports", headers=h)
    assert r.status_code == 200
    assert "Abuja 2026" in r.text


def test_instructor_can_view_cohort_matrix(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh, _ = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "inst@a.edu")
    r = app_client.get(f"/instructor/reports/cohort/{coh.id}", headers=h)
    assert r.status_code == 200
    assert "a@stu.edu" in r.text
    assert "Ch1 Test" in r.text


def test_admin_can_view_cohort_matrix(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    coh, _ = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "admin@a.edu")
    r = app_client.get(f"/instructor/reports/cohort/{coh.id}", headers=h)
    assert r.status_code == 200


def test_student_transcript_view(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh, stu_a = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "inst@a.edu")
    r = app_client.get(f"/instructor/reports/student/{stu_a.id}", headers=h)
    assert r.status_code == 200
    assert "Ch1 Test" in r.text


def test_cohort_csv_export(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh, _ = _seed_cohort(admin_session, tenant_a.id)
    h = _login(app_client, "inst@a.edu")
    r = app_client.get(f"/instructor/reports/cohort/{coh.id}.csv", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert f"cohort-{coh.id}.csv" in r.headers.get("content-disposition", "")
    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    # header + 2 student rows
    assert len(lines) == 3
    assert "a@stu.edu" in r.text and "b@stu.edu" in r.text


def test_cross_tenant_cohort_404(app_client, admin_session, tenant_a, tenant_b):
    _seed_login(admin_session, tenant_a, "inst@a.edu", "instructor")
    coh_b = Cohort(tenant_id=tenant_b.id, name="Beta", discipline="networking", status="active")
    admin_session.add(coh_b)
    admin_session.commit()
    admin_session.refresh(coh_b)
    h = _login(app_client, "inst@a.edu")
    assert app_client.get(f"/instructor/reports/cohort/{coh_b.id}", headers=h).status_code == 404
