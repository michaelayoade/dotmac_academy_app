"""Completion recomputation service (Slice 2c)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.models.assessment import Activity, Question, QuestionBank, Score, Submission
from app.models.attempt import ActivityAttempt
from app.models.certificate import Certificate
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.learning_event import LearningEvent
from app.models.notification import Notification
from app.models.person import Person
from app.services import attempts, certificates, completion
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


def test_concurrent_first_recomputes_create_one_completion_and_certificate(
    admin_engine, admin_session, tenant_a
):
    """First-creation serialization also covers callers without a Person lock."""
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="race@a.edu", first_name="Race", last_name="Learner")
    admin_session.add(person)
    admin_session.flush()
    course, first, last = _course_with_two_activities(admin_session, tid)
    _pass(admin_session, tid, person, first)
    _pass(admin_session, tid, person, last)
    person_id, course_id = person.id, course.id
    admin_session.commit()
    factory = sessionmaker(bind=admin_engine, autoflush=False)
    start = Barrier(2)

    def recompute(_):
        with factory() as db:
            start.wait(timeout=5)
            completion = recompute_completion(
                db, tenant_id=tid, person_id=person_id, course_id=course_id
            )
            identity = completion.id, completion.completed_at
            db.commit()
            return identity

    with ThreadPoolExecutor(max_workers=2) as pool:
        identities = list(pool.map(recompute, (1, 2)))
    assert identities[0] == identities[1]
    assert identities[0][1] is not None
    admin_session.expire_all()
    completion = admin_session.query(CourseCompletion).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id
    ).one()
    assert completion.pct == 1
    assert completion.status == "completed"
    assert admin_session.query(Certificate).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id
    ).count() == 1
    assert admin_session.query(LearningEvent).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id, kind="certificate_earned"
    ).count() == 1


def _learner_with_open_quiz(db, tid):
    person = Person(tenant_id=tid, email="mixed@a.edu", first_name="Mixed", last_name="Learner")
    db.add(person)
    course, quiz, last = _course_with_two_activities(db, tid)
    bank = QuestionBank(tenant_id=tid, course_id=course.id, chapter_number=1, kind="chapter", version=1)
    db.add(bank)
    db.flush()
    db.add(Question(
        tenant_id=tid, bank_id=bank.id, ext_id="q1", stem="Pick A", type="single",
        options=["A", "B"], correct=["A"], rubric_category="recall", explanation="", weight=1,
    ))
    quiz.bank_id = bank.id
    quiz.question_count = 1
    attempt = ActivityAttempt(
        tenant_id=tid, activity_id=quiz.id, person_id=person.id,
        question_ext_ids=["q1"], started_at=datetime.now(UTC),
    )
    db.add(attempt)
    db.flush()
    return person, course, quiz, last, attempt


@pytest.mark.parametrize("close_first", [False, True], ids=["direct-submit", "close-then-submit"])
def test_admission_and_certificate_writers_preserve_fk_consequences_without_deadlock(
    admin_engine, admin_session, tenant_a, monkeypatch, close_first
):
    """Cross actual admission/aggregate locks before writing real People FKs.

    A holds the admission lock and approaches completion; B holds completion
    and must write certificate_earned plus its notification. FOR UPDATE on
    People would block B's FK checks and create a lock cycle or lose these
    best-effort consequences, even if both callers eventually report success.
    """
    tid = tenant_a.id
    person, course, quiz, last, attempt = _learner_with_open_quiz(admin_session, tid)
    _pass(admin_session, tid, person, quiz)
    _pass(admin_session, tid, person, last)
    completed_at = datetime(2026, 6, 27, tzinfo=UTC)
    admin_session.add(CourseCompletion(
        tenant_id=tid, person_id=person.id, course_id=course.id,
        status="completed", pct=1, completed_at=completed_at,
    ))
    person_id, course_id, quiz_id, attempt_id = person.id, course.id, quiz.id, attempt.id
    admin_session.commit()
    assert admin_session.query(Certificate).filter_by(tenant_id=tid).count() == 0
    factory = sessionmaker(bind=admin_engine, autoflush=False)
    both_locks = Barrier(2)
    real_ensure = completion.ensure_locked_completion
    real_lock = certificates.lock_existing_completion

    def after_admission(db, **kwargs):
        # submit_activity already acquired its real Person admission lock.
        both_locks.wait(timeout=5)
        return real_ensure(db, **kwargs)

    def after_completion_lock(db, **kwargs):
        aggregate = real_lock(db, **kwargs)
        assert aggregate is not None
        both_locks.wait(timeout=5)
        return aggregate

    monkeypatch.setattr(completion, "ensure_locked_completion", after_admission)
    monkeypatch.setattr(certificates, "lock_existing_completion", after_completion_lock)

    def submit():
        with factory() as db:
            try:
                db.execute(text("SET LOCAL lock_timeout = '2s'"))
                db.execute(text("SET LOCAL statement_timeout = '8s'"))
                activity = db.get(Activity, quiz_id)
                if close_first:
                    closed = attempts.close_open_attempt(
                        db, tenant_id=tid, person_id=person_id, activity_id=quiz_id
                    )
                    assert closed is not None and closed.id == attempt_id
                score = submit_activity(
                    db, tenant_id=tid, person_id=person_id, activity=activity,
                    answers={"q1": ["A"]}, only_ext_ids=["q1"],
                )
                assert score is not None and score.passed
                score_id = score.id
                db.commit()
                return score_id
            finally:
                db.rollback()

    def issue():
        with factory() as db:
            try:
                db.execute(text("SET LOCAL lock_timeout = '2s'"))
                db.execute(text("SET LOCAL statement_timeout = '8s'"))
                cert = certificates.issue_certificate(
                    db, tenant_id=tid, person_id=person_id, course_id=course_id
                )
                certificate_id = cert.id
                db.commit()
                return certificate_id
            finally:
                db.rollback()

    with ThreadPoolExecutor(max_workers=2) as pool:
        submit_future = pool.submit(submit)
        issue_future = pool.submit(issue)
        score_id = submit_future.result(timeout=15)
        certificate_id = issue_future.result(timeout=15)
    admin_session.expire_all()
    assert admin_session.get(Score, score_id).passed
    assert admin_session.query(Submission).filter_by(tenant_id=tid, activity_id=quiz_id).count() == 2
    cert = admin_session.query(Certificate).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id
    ).one()
    assert cert.id == certificate_id
    earned = admin_session.query(LearningEvent).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id, kind="certificate_earned"
    ).one()
    assert earned.detail["serial"] == cert.serial
    assert admin_session.query(Notification).filter_by(
        tenant_id=tid, person_id=person_id, kind="certificate"
    ).count() == 1
    aggregate = admin_session.query(CourseCompletion).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id
    ).one()
    assert aggregate.status == "completed" and aggregate.completed_at == completed_at
    assert (admin_session.get(ActivityAttempt, attempt_id).submitted_at is not None) == close_first


def test_attempt_close_and_submit_admission_locks_remain_mutually_exclusive(
    admin_engine, admin_session, tenant_a
):
    """NO KEY UPDATE must serialize admission; KEY SHARE would be too weak."""
    tid = tenant_a.id
    person, _course, quiz, _last, attempt = _learner_with_open_quiz(admin_session, tid)
    person_id, quiz_id, attempt_id = person.id, quiz.id, attempt.id
    admin_session.commit()
    factory = sessionmaker(bind=admin_engine, autoflush=False)
    with factory() as holder, factory() as contender:
        try:
            closed = attempts.close_open_attempt(
                holder, tenant_id=tid, person_id=person_id, activity_id=quiz_id
            )
            assert closed is not None and closed.id == attempt_id
            contender.execute(text("SET LOCAL lock_timeout = '250ms'"))
            activity = contender.get(Activity, quiz_id)
            with pytest.raises(OperationalError) as refused:
                submit_activity(
                    contender, tenant_id=tid, person_id=person_id,
                    activity=activity, answers={"q1": ["A"]},
                )
            assert refused.value.orig.sqlstate == "55P03"
            contender.rollback()
            holder.commit()
            score = submit_activity(
                contender, tenant_id=tid, person_id=person_id,
                activity=activity, answers={"q1": ["A"]},
            )
            assert score is not None and score.passed
            contender.commit()
        finally:
            contender.rollback()
            holder.rollback()
    admin_session.expire_all()
    assert admin_session.query(Submission).filter_by(tenant_id=tid, activity_id=quiz_id).count() == 1
    assert admin_session.get(ActivityAttempt, attempt_id).submitted_at is not None
