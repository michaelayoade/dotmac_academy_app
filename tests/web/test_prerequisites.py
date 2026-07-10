"""Course prerequisite enforcement (Slice 2e)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.assessment import Activity
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.prerequisite import CoursePrerequisite
from app.services.security import hash_password

H = {"Host": "alpha.localhost"}


def _course(admin_session, tid, slug):
    c = Course(tenant_id=tid, slug=slug, title=slug.title(), discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    act = Activity(tenant_id=tid, course_id=c.id, chapter_number=1, type="mcq_test",
                   title=f"{slug} act", pass_threshold=0.6)
    admin_session.add(act)
    admin_session.flush()
    return c, act


def _setup(admin_session, tenant):
    """Learner entitled to course B which requires course A. Returns (person, A, B, actB)."""
    p = Person(tenant_id=tenant.id, email="pre@a.edu", first_name="Pre", last_name="Req")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(UserCredential(tenant_id=tenant.id, person_id=p.id, email="pre@a.edu",
                                     password_hash=hash_password("password1")))
    a, _ = _course(admin_session, tenant.id, "alpha")
    b, act_b = _course(admin_session, tenant.id, "beta")
    coh = Cohort(tenant_id=tenant.id, name="C", discipline="networking", status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(Enrollment(tenant_id=tenant.id, cohort_id=coh.id, person_id=p.id,
                                 role_in_cohort="student", status="active"))
    # Entitle to both A and B so only the prerequisite gates B.
    admin_session.add(CourseOffering(tenant_id=tenant.id, cohort_id=coh.id, course_id=a.id, status="active"))
    admin_session.add(CourseOffering(tenant_id=tenant.id, cohort_id=coh.id, course_id=b.id, status="active"))
    admin_session.add(CoursePrerequisite(tenant_id=tenant.id, course_id=b.id, requires_course_id=a.id))
    admin_session.flush()
    return p, a, b, act_b


def _login(app_client):
    app_client.post("/login", headers=H, data={"email": "pre@a.edu", "password": "password1"})


def _cleanup(admin_session, tenant):
    admin_session.query(Course).filter(Course.tenant_id == tenant.id).delete()
    admin_session.query(Cohort).filter(Cohort.tenant_id == tenant.id).delete()
    admin_session.commit()


def test_prerequisite_incomplete_blocks_access(app_client, admin_session, tenant_a):
    p, a, b, act_b = _setup(admin_session, tenant_a)
    admin_session.commit()  # A not completed
    _login(app_client)
    try:
        assert app_client.get(f"/activities/{act_b.id}", headers=H).status_code == 403
    finally:
        _cleanup(admin_session, tenant_a)


def test_prerequisite_completed_allows_access(app_client, admin_session, tenant_a):
    p, a, b, act_b = _setup(admin_session, tenant_a)
    admin_session.add(CourseCompletion(tenant_id=tenant_a.id, person_id=p.id, course_id=a.id,
                                       status="completed", pct=1.0, completed_at=datetime.now(UTC)))
    admin_session.commit()
    _login(app_client)
    try:
        assert app_client.get(f"/activities/{act_b.id}", headers=H).status_code == 200
    finally:
        _cleanup(admin_session, tenant_a)
