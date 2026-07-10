"""Completion recomputation service (Slice 2c)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.assessment import Activity, Question, QuestionBank, Score, Submission
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.person import Person
from app.services.assessment import submit_activity
from app.services.completion import recompute_completion


def _course_with_two_activities(db, tid):
    c = Course(tenant_id=tid, slug="net", title="Net", discipline="networking",
               source_ref="x", version=1)
    db.add(c)
    db.flush()
    a1 = Activity(tenant_id=tid, course_id=c.id, chapter_number=1, type="mcq_test",
                  title="A1", pass_threshold=0.6)
    a2 = Activity(tenant_id=tid, course_id=c.id, chapter_number=2, type="mcq_test",
                  title="A2", pass_threshold=0.6)
    db.add_all([a1, a2])
    db.flush()
    return c, a1, a2


def _pass(db, tid, person, activity, frac=1.0):
    sub = Submission(tenant_id=tid, activity_id=activity.id, person_id=person.id,
                     answers={}, attempt_no=1)
    db.add(sub)
    db.flush()
    db.add(Score(tenant_id=tid, submission_id=sub.id, score=frac * 10, max_score=10,
                 fraction=frac, passed=frac >= activity.pass_threshold, per_item=[], source="auto"))
    db.flush()


def test_partial_then_full_completion(admin_session, tenant_a):
    tid = tenant_a.id
    p = Person(tenant_id=tid, email="c@a.edu", first_name="C", last_name="X")
    admin_session.add(p)
    admin_session.flush()
    c, a1, a2 = _course_with_two_activities(admin_session, tid)

    # Pass one of two → in_progress, 0.5, no completed_at.
    _pass(admin_session, tid, p, a1)
    rec = recompute_completion(admin_session, tenant_id=tid, person_id=p.id, course_id=c.id)
    assert rec.status == "in_progress"
    assert rec.pct == 0.5
    assert rec.completed_at is None

    # Pass the second → completed, 1.0, completed_at stamped.
    _pass(admin_session, tid, p, a2)
    now = datetime(2026, 6, 27, tzinfo=UTC)
    rec = recompute_completion(admin_session, tenant_id=tid, person_id=p.id, course_id=c.id, now=now)
    assert rec.status == "completed"
    assert rec.pct == 1.0
    assert rec.completed_at == now

    # Idempotent: recompute keeps the original completed_at (no re-stamp).
    rec2 = recompute_completion(admin_session, tenant_id=tid, person_id=p.id, course_id=c.id,
                                now=datetime(2026, 7, 1, tzinfo=UTC))
    assert rec2.completed_at == now
    # And there is exactly one record for the pair.
    n = admin_session.query(CourseCompletion).filter(
        CourseCompletion.tenant_id == tid, CourseCompletion.person_id == p.id,
        CourseCompletion.course_id == c.id).count()
    assert n == 1
    admin_session.rollback()


def test_submit_activity_updates_completion(admin_session, tenant_a):
    """Slice 2c: grading a submission recomputes the completion record."""
    tid = tenant_a.id
    p = Person(tenant_id=tid, email="d@a.edu", first_name="D", last_name="X")
    admin_session.add(p)
    admin_session.flush()
    c = Course(tenant_id=tid, slug="solo", title="Solo", discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    bank = QuestionBank(tenant_id=tid, course_id=c.id, chapter_number=1, kind="chapter", version=1)
    admin_session.add(bank)
    admin_session.flush()
    admin_session.add(Question(tenant_id=tid, bank_id=bank.id, ext_id="q1", stem="Pick A",
                               type="single", options=["A", "B"], correct=["A"],
                               rubric_category="recall", explanation="", weight=1))
    act = Activity(tenant_id=tid, course_id=c.id, chapter_number=1, type="mcq_test",
                   bank_id=bank.id, title="Solo Ch1", pass_threshold=0.6)
    admin_session.add(act)
    admin_session.flush()

    submit_activity(admin_session, tenant_id=tid, person_id=p.id, activity=act,
                    answers={"q1": ["A"]})

    rec = admin_session.query(CourseCompletion).filter(
        CourseCompletion.tenant_id == tid, CourseCompletion.person_id == p.id,
        CourseCompletion.course_id == c.id).one()
    assert rec.status == "completed"
    assert rec.pct == 1.0
    admin_session.rollback()
