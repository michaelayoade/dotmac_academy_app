"""Regression tests for the review-correction pass (2026-07-30).

Each test pins one confirmed defect so it cannot silently return.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.prerequisite import CoursePrerequisite
from app.models.success_queue import SuccessQueueEntry
from app.services import learning_events, reminders, success_queue
from app.services.entitlements import course_access_states
from app.services.gradebook import course_grade


def _course(admin_session, tenant, slug):
    c = Course(tenant_id=tenant.id, slug=slug, title=slug.title(),
               discipline="fiber", source_ref="t@1", status="published")
    admin_session.add(c)
    admin_session.flush()
    return c


def _enrol(admin_session, tenant, person, course, *, track_id=None, days_ago=1):
    cohort = Cohort(tenant_id=tenant.id, name=f"C {course.slug}", discipline="fiber", status="active")
    admin_session.add(cohort)
    admin_session.flush()
    enr = Enrollment(tenant_id=tenant.id, cohort_id=cohort.id, person_id=person.id,
                     role_in_cohort="student", status="active", track_id=track_id)
    admin_session.add(enr)
    off = CourseOffering(tenant_id=tenant.id, cohort_id=cohort.id, course_id=course.id, status="active")
    admin_session.add(off)
    admin_session.flush()
    enr.created_at = datetime.now(UTC) - timedelta(days=days_ago)
    admin_session.flush()
    return cohort


def test_explicit_prerequisite_locks_course_on_dashboard(admin_session, tenant_a):
    """course_access_states must reflect explicit CoursePrerequisite, not only
    track order — else My Courses shows Start and the chapter route 403s."""
    person = Person(tenant_id=tenant_a.id, email="prereq@a.edu", first_name="P", last_name="R")
    admin_session.add(person)
    admin_session.flush()
    intro = _course(admin_session, tenant_a, "intro-x")
    advanced = _course(admin_session, tenant_a, "advanced-x")
    _enrol(admin_session, tenant_a, person, advanced)
    admin_session.add(CoursePrerequisite(tenant_id=tenant_a.id, course_id=advanced.id,
                                         requires_course_id=intro.id))
    admin_session.commit()

    states = course_access_states(admin_session, tenant_id=tenant_a.id, person_id=person.id)
    assert states[advanced.id].locked is True
    assert states[advanced.id].locked_until_course_id == intro.id


def test_below_passing_counts_a_genuine_zero(admin_session, tenant_a):
    """gradebook.graded distinguishes a real 0% from never-submitted, so the
    below-passing rule fires for a learner who scored 0, not just >0."""
    person = Person(tenant_id=tenant_a.id, email="zero@a.edu", first_name="Z", last_name="Ero")
    admin_session.add(person)
    course = _course(admin_session, tenant_a, "zero-course")
    _enrol(admin_session, tenant_a, person, course)
    act = Activity(tenant_id=tenant_a.id, course_id=course.id, chapter_number=1,
                   type="mcq_test", title="Q", pass_threshold=0.6)
    admin_session.add(act)
    admin_session.flush()
    sub = Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=person.id, answers={})
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tenant_a.id, submission_id=sub.id, score=0, max_score=10,
                            fraction=0.0, passed=False, per_item=[], source="auto"))
    admin_session.commit()

    grade = course_grade(admin_session, tenant_id=tenant_a.id, person_id=person.id, course_id=course.id)
    assert grade["per_activity"][0]["graded"] is True   # a real 0, not "unattempted"
    hit = success_queue._rule_below_passing(
        admin_session, tenant_id=tenant_a.id, person_id=person.id,
        course_ids=[course.id], min_grade_pct=60,
    )
    assert hit is not None and hit[0]["grade_pct"] == 0


def test_severity_order_is_rank_not_text(admin_session, tenant_a):
    """list_entries returns high before medium before low."""
    person = Person(tenant_id=tenant_a.id, email="sev@a.edu", first_name="S", last_name="V")
    admin_session.add(person)
    cohort = Cohort(tenant_id=tenant_a.id, name="Sev", discipline="fiber", status="active")
    admin_session.add(cohort)
    admin_session.flush()
    for sev in ("low", "high", "medium"):
        admin_session.add(SuccessQueueEntry(
            tenant_id=tenant_a.id, person_id=person.id, cohort_id=cohort.id,
            reason_kind=f"r_{sev}", severity=sev, supporting_facts={},
            recommended_action="x", status="open", detected_at=datetime.now(UTC),
        ))
    admin_session.commit()
    rows = success_queue.list_entries(admin_session, tenant_id=tenant_a.id)
    assert [r["entry"].severity for r in rows][:3] == ["high", "medium", "low"]


def test_graded_reminder_skips_auto_scores(admin_session, tenant_a):
    """Auto-graded quiz results must not generate 'graded' reminders."""
    person = Person(tenant_id=tenant_a.id, email="autg@a.edu", first_name="A", last_name="G")
    admin_session.add(person)
    course = _course(admin_session, tenant_a, "autog-course")
    _enrol(admin_session, tenant_a, person, course)
    act = Activity(tenant_id=tenant_a.id, course_id=course.id, chapter_number=1,
                   type="mcq_test", title="Quiz", pass_threshold=0.6)
    admin_session.add(act)
    admin_session.flush()
    sub = Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=person.id, answers={})
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tenant_a.id, submission_id=sub.id, score=9, max_score=10,
                            fraction=0.9, passed=True, per_item=[], source="auto"))
    admin_session.commit()
    events = reminders._detect_events(admin_session, tenant_id=tenant_a.id, person_id=person.id,
                                      now=datetime.now(UTC), inactivity_days=7)
    assert not any(e["kind"] == "graded" for e in events)


def test_ledger_once_per_subject_is_idempotent(admin_session, tenant_a):
    """A second chapter_completed for the same subject is a no-op (DB-guarded)."""
    person = Person(tenant_id=tenant_a.id, email="ledg@a.edu", first_name="L", last_name="G")
    admin_session.add(person)
    course = _course(admin_session, tenant_a, "ledger-course")
    admin_session.flush()
    from uuid import uuid4
    subject = uuid4()
    first = learning_events.record(admin_session, tenant_id=tenant_a.id, person_id=person.id,
                                   kind="chapter_completed", course_id=course.id, subject_id=subject)
    second = learning_events.record(admin_session, tenant_id=tenant_a.id, person_id=person.id,
                                    kind="chapter_completed", course_id=course.id, subject_id=subject)
    admin_session.commit()
    assert first is not None and second is None
