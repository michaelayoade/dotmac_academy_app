# tests/services/test_agenda.py
"""Unit tests for app/services/agenda.py — upcoming_for_person."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.assessment import Activity, Question, QuestionBank
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.pacing import OfferingActivity
from app.models.person import Person
from app.services.agenda import upcoming_for_person


def _seed_course(db, tid, slug, title="Course"):
    c = Course(
        tenant_id=tid, slug=slug, title=title, discipline="networking",
        source_ref="x", version=1, status="published",
    )
    db.add(c)
    db.flush()
    return c


def _seed_activity(db, tid, course_id, title="Act"):
    bank = QuestionBank(tenant_id=tid, course_id=course_id, chapter_number=1, kind="chapter", version=1)
    db.add(bank)
    db.flush()
    db.add(Question(
        tenant_id=tid, bank_id=bank.id, ext_id="q1", stem="Q?", type="single",
        options=["A", "B"], correct=["A"], rubric_category="recall", explanation="", weight=1,
    ))
    act = Activity(
        tenant_id=tid, course_id=course_id, chapter_number=1,
        type="mcq_test", bank_id=bank.id, title=title, pass_threshold=0.6,
    )
    db.add(act)
    db.flush()
    return act


def _enroll_with_offering(db, tid, person_id, course_id, *, starts_at=None, ends_at=None):
    coh = Cohort(tenant_id=tid, name="Coh", discipline="networking", status="active")
    db.add(coh)
    db.flush()
    db.add(Enrollment(tenant_id=tid, cohort_id=coh.id, person_id=person_id,
                      role_in_cohort="student", status="active"))
    off = CourseOffering(
        tenant_id=tid, cohort_id=coh.id, course_id=course_id,
        status="active", starts_at=starts_at, ends_at=ends_at,
    )
    db.add(off)
    db.flush()
    return coh, off


def test_future_due_at_appears(admin_session, tenant_a):
    """A pacing due_at in the future on an accessible course appears in the agenda."""
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="ag_due@a.edu", first_name="A", last_name="G")
    admin_session.add(person)
    admin_session.flush()

    course = _seed_course(admin_session, tid, "ag-due", "Due Course")
    act = _seed_activity(admin_session, tid, course.id, "Quiz 1")
    _, off = _enroll_with_offering(admin_session, tid, person.id, course.id)

    future = datetime.now(UTC) + timedelta(days=3)
    admin_session.add(OfferingActivity(
        tenant_id=tid, offering_id=off.id, activity_id=act.id, due_at=future,
    ))
    admin_session.flush()

    items = upcoming_for_person(admin_session, tenant_id=tid, person_id=person.id)
    titles = [i["title"] for i in items]
    admin_session.rollback()

    assert "Quiz 1" in titles


def test_past_items_excluded(admin_session, tenant_a):
    """A pacing due_at in the past must not appear."""
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="ag_past@a.edu", first_name="A", last_name="P")
    admin_session.add(person)
    admin_session.flush()

    course = _seed_course(admin_session, tid, "ag-past", "Past Course")
    act = _seed_activity(admin_session, tid, course.id, "Old Quiz")
    _, off = _enroll_with_offering(admin_session, tid, person.id, course.id)

    past = datetime.now(UTC) - timedelta(days=1)
    admin_session.add(OfferingActivity(
        tenant_id=tid, offering_id=off.id, activity_id=act.id, due_at=past,
    ))
    admin_session.flush()

    items = upcoming_for_person(admin_session, tenant_id=tid, person_id=person.id)
    titles = [i["title"] for i in items]
    admin_session.rollback()

    assert "Old Quiz" not in titles


def test_non_accessible_course_excluded(admin_session, tenant_a):
    """Activity due_at from a course the person is NOT enrolled in is excluded."""
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="ag_noac@a.edu", first_name="A", last_name="N")
    other = Person(tenant_id=tid, email="ag_noac2@a.edu", first_name="B", last_name="N")
    admin_session.add(person)
    admin_session.add(other)
    admin_session.flush()

    accessible_course = _seed_course(admin_session, tid, "ag-acc", "Accessible")
    inaccessible_course = _seed_course(admin_session, tid, "ag-noacc", "Inaccessible")
    act_inacc = _seed_activity(admin_session, tid, inaccessible_course.id, "Secret Quiz")

    # Enroll person in accessible course only; other person in inaccessible
    _enroll_with_offering(admin_session, tid, person.id, accessible_course.id)
    _, off_inacc = _enroll_with_offering(admin_session, tid, other.id, inaccessible_course.id)

    future = datetime.now(UTC) + timedelta(days=2)
    admin_session.add(OfferingActivity(
        tenant_id=tid, offering_id=off_inacc.id, activity_id=act_inacc.id, due_at=future,
    ))
    admin_session.flush()

    items = upcoming_for_person(admin_session, tenant_id=tid, person_id=person.id)
    titles = [i["title"] for i in items]
    admin_session.rollback()

    assert "Secret Quiz" not in titles


def test_ordering_chronological(admin_session, tenant_a):
    """Multiple future items are returned in chronological order."""
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="ag_ord@a.edu", first_name="A", last_name="O")
    admin_session.add(person)
    admin_session.flush()

    course = _seed_course(admin_session, tid, "ag-ord", "Ordered Course")
    act1 = _seed_activity(admin_session, tid, course.id, "Quiz Early")
    act2 = _seed_activity(admin_session, tid, course.id, "Quiz Late")
    _, off = _enroll_with_offering(admin_session, tid, person.id, course.id)

    soon = datetime.now(UTC) + timedelta(days=1)
    later = datetime.now(UTC) + timedelta(days=5)
    admin_session.add(OfferingActivity(
        tenant_id=tid, offering_id=off.id, activity_id=act1.id, due_at=soon,
    ))
    admin_session.add(OfferingActivity(
        tenant_id=tid, offering_id=off.id, activity_id=act2.id, due_at=later,
    ))
    admin_session.flush()

    items = upcoming_for_person(admin_session, tenant_id=tid, person_id=person.id)
    titles = [i["title"] for i in items if i["kind"] == "due"]
    admin_session.rollback()

    assert titles.index("Quiz Early") < titles.index("Quiz Late")


def test_offering_window_events_appear(admin_session, tenant_a):
    """Future starts_at and ends_at on an offering appear as agenda items."""
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="ag_win@a.edu", first_name="A", last_name="W")
    admin_session.add(person)
    admin_session.flush()

    course = _seed_course(admin_session, tid, "ag-win", "Window Course")
    future_start = datetime.now(UTC) + timedelta(days=2)
    future_end = datetime.now(UTC) + timedelta(days=30)
    _enroll_with_offering(
        admin_session, tid, person.id, course.id,
        starts_at=future_start, ends_at=future_end,
    )
    admin_session.flush()

    items = upcoming_for_person(admin_session, tenant_id=tid, person_id=person.id)
    kinds = {i["kind"] for i in items}
    admin_session.rollback()

    assert "opens" in kinds
    assert "closes" in kinds
