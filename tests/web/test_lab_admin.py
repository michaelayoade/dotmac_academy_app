"""Tests for the instructor lab monitor + override — Task 10."""

from __future__ import annotations

from uuid import uuid4

from app.services.security import hash_password
from app.services.bootstrap import ensure_roles
from app.models.person import Person
from app.models.auth import UserCredential
from app.models.rbac import PersonRole
from app.models.assessment import Activity, Submission, Score


def _login_instructor(app_client, admin_session, tenant):
    """Seed an instructor person, log in via TestClient, return Host header dict."""
    roles = ensure_roles(admin_session, tenant.id)
    p = Person(tenant_id=tenant.id, email="li@a.edu", first_name="Lab", last_name="Instr")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email="li@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.add(
        PersonRole(tenant_id=tenant.id, person_id=p.id, role_id=roles["instructor"].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": "li@a.edu", "password": "password1"})
    return h


def test_student_forbidden_on_monitor(app_client, admin_session, tenant_a):
    """A user with only the student role gets 403 on GET /instructor/labs."""
    roles = ensure_roles(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="ls@a.edu", first_name="S", last_name="T")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant_a.id,
            person_id=p.id,
            email="ls@a.edu",
            password_hash=hash_password("password1"),
        )
    )
    admin_session.add(
        PersonRole(tenant_id=tenant_a.id, person_id=p.id, role_id=roles["student"].id)
    )
    admin_session.commit()

    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": "ls@a.edu", "password": "password1"})
    assert app_client.get("/instructor/labs", headers=h).status_code == 403


def test_instructor_override_creates_override_score(app_client, admin_session, tenant_a):
    """An instructor override on a seeded lab Submission creates a Score(source='override')."""
    h = _login_instructor(app_client, admin_session, tenant_a)

    # Seed a lab activity + a student submission to override.
    student = Person(tenant_id=tenant_a.id, email="learner@a.edu", first_name="L", last_name="N")
    admin_session.add(student)
    activity = Activity(
        tenant_id=tenant_a.id, course_id=uuid4(), type="lab", title="VLAN Lab",
        pass_threshold=0.7,
    )
    admin_session.add(activity)
    admin_session.flush()
    sub = Submission(
        tenant_id=tenant_a.id, activity_id=activity.id, person_id=student.id,
        answers={"seed": {"o": 5}, "instance": "dal-x"},
    )
    admin_session.add(sub)
    admin_session.commit()
    admin_session.refresh(sub)

    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(
        f"/instructor/labs/scores/{sub.id}/override",
        headers={**h, "x-csrf-token": csrf},
        data={"score_value": "8", "max_score": "10", "reason": "manual lab review"},
        follow_redirects=False,
    )
    assert r.status_code in (200, 303)

    override = (
        admin_session.query(Score)
        .filter(Score.submission_id == sub.id, Score.source == "override")
        .one_or_none()
    )
    assert override is not None
    assert override.score == 8.0
    assert override.max_score == 10.0
    assert override.override_reason == "manual lab review"
