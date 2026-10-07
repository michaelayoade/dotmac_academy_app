"""Dedicated instructor cohort workspace web coverage."""

from __future__ import annotations

from app.models.assessment import Activity
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Chapter, Course
from app.models.offering import CourseOffering
from app.models.person import Person
from tests.web.test_reports import _login, _seed_login


def _seed_detail(admin_session, tenant):
    cohort = Cohort(
        tenant_id=tenant.id,
        name="Fiber Academy 2027",
        discipline="networking",
        status="active",
        delivery_mode="blended",
    )
    course = Course(
        tenant_id=tenant.id,
        slug="fiber-safety",
        title="Fiber Safety",
        discipline="networking",
        source_ref="test",
        version=2,
        status="published",
    )
    learner = Person(
        tenant_id=tenant.id,
        email="learner@a.edu",
        first_name="Ada",
        last_name="Learner",
    )
    facilitator = Person(
        tenant_id=tenant.id,
        email="facilitator@a.edu",
        first_name="Femi",
        last_name="Facilitator",
    )
    admin_session.add_all([cohort, course, learner, facilitator])
    admin_session.flush()
    admin_session.add_all(
        [
            CourseOffering(
                tenant_id=tenant.id,
                cohort_id=cohort.id,
                course_id=course.id,
                status="active",
            ),
            Chapter(
                tenant_id=tenant.id,
                course_id=course.id,
                number=1,
                title="Module One",
                part="Foundations",
                body_html="<p>Safety first.</p>",
                order_index=1,
            ),
            Activity(
                tenant_id=tenant.id,
                course_id=course.id,
                chapter_number=1,
                type="mcq_test",
                title="Safety Check",
                pass_threshold=0.7,
            ),
            Enrollment(
                tenant_id=tenant.id,
                cohort_id=cohort.id,
                person_id=learner.id,
                role_in_cohort="student",
                status="active",
            ),
            Enrollment(
                tenant_id=tenant.id,
                cohort_id=cohort.id,
                person_id=facilitator.id,
                role_in_cohort="instructor",
                status="active",
            ),
            CourseCompletion(
                tenant_id=tenant.id,
                person_id=learner.id,
                course_id=course.id,
                status="in_progress",
                pct=0.6,
            ),
        ]
    )
    admin_session.commit()
    return cohort


def test_admin_sees_complete_cohort_workspace(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    cohort = _seed_detail(admin_session, tenant_a)
    response = app_client.get(
        f"/instructor/cohorts/{cohort.id}",
        headers=_login(app_client, "admin@a.edu"),
    )

    assert response.status_code == 200
    assert "Fiber Academy 2027" in response.text
    assert "learner@a.edu" in response.text
    assert "60%" in response.text
    assert "Fiber Safety" in response.text
    assert "Module One" in response.text
    assert "Safety Check" in response.text
    assert "facilitator@a.edu" in response.text
    assert f'/instructor/gradebook/{cohort.id}' in response.text
    assert f'/instructor/reports/cohort/{cohort.id}' in response.text


def test_cohort_workspace_student_table_is_paginated(app_client, admin_session, tenant_a):
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    cohort = Cohort(tenant_id=tenant_a.id, name="Large Cohort", discipline="fiber", status="active")
    admin_session.add(cohort)
    admin_session.flush()
    for index in range(13):
        learner = Person(
            tenant_id=tenant_a.id,
            email=f"learner{index:02d}@a.edu",
            first_name=f"Learner {index:02d}",
            last_name="Student",
        )
        admin_session.add(learner)
        admin_session.flush()
        admin_session.add(
            Enrollment(
                tenant_id=tenant_a.id,
                cohort_id=cohort.id,
                person_id=learner.id,
                role_in_cohort="student",
                status="active",
            )
        )
    admin_session.commit()

    response = app_client.get(
        f"/instructor/cohorts/{cohort.id}?limit=6&offset=0",
        headers=_login(app_client, "admin@a.edu"),
    )

    assert response.status_code == 200
    assert "Showing <strong>1</strong> to <strong>6</strong> of <strong>13</strong> students" in response.text
    assert "learner00@a.edu" in response.text
    assert "learner05@a.edu" in response.text
    assert "learner06@a.edu" not in response.text


def test_cohort_workspace_is_tenant_scoped(app_client, admin_session, tenant_a, tenant_b):
    _seed_login(admin_session, tenant_a, "admin@a.edu", "admin")
    other = Cohort(tenant_id=tenant_b.id, name="Other Tenant", discipline="fiber", status="active")
    admin_session.add(other)
    admin_session.commit()

    response = app_client.get(
        f"/instructor/cohorts/{other.id}",
        headers=_login(app_client, "admin@a.edu"),
    )

    assert response.status_code == 404
