"""Entrance assessment: grade an applicant's exam into a competency profile."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models.admissions import Applicant
from app.models.assessment import Question, QuestionBank
from app.models.cohort import Cohort
from app.models.course import Course
from app.services import admissions, entrance_exam, onboarding
from app.services.exceptions import BadRequestError


def _bank_with_questions(admin_session, tenant):
    course = Course(
        tenant_id=tenant.id, slug=f"c-{uuid.uuid4().hex[:6]}", title="Intake",
        discipline="fiber", source_ref="x", version=1,
    )
    admin_session.add(course)
    admin_session.flush()
    bank = QuestionBank(tenant_id=tenant.id, course_id=course.id, chapter_number=1, kind="chapter", version=1)
    admin_session.add(bank)
    admin_session.flush()
    for ext, cat in [("q1", "numeracy"), ("q2", "numeracy"), ("q3", "safety"), ("q4", "safety")]:
        admin_session.add(Question(
            tenant_id=tenant.id, bank_id=bank.id, ext_id=ext, stem="?", type="single",
            options=["A", "B"], correct=["A"], rubric_category="recall", category=cat,
            explanation="", weight=1,
        ))
    admin_session.flush()
    return bank


def _cohort(admin_session, tenant, bank=None):
    c = Cohort(
        tenant_id=tenant.id, name="FA2", discipline="fiber", status="active",
        entrance_bank_id=(bank.id if bank else None),
    )
    admin_session.add(c)
    admin_session.flush()
    return c


def _applicant(admin_session, tenant, cohort):
    a = Applicant(
        tenant_id=tenant.id, email=f"a{uuid.uuid4().hex[:6]}@x.ex", first_name="A",
        last_name="B", status="applied", cohort_id=cohort.id,
    )
    admin_session.add(a)
    admin_session.flush()
    return a


def test_grade_records_profile_and_level(admin_session, tenant_a):
    bank = _bank_with_questions(admin_session, tenant_a)
    applicant = _applicant(admin_session, tenant_a, _cohort(admin_session, tenant_a, bank))
    # numeracy both correct -> 1.0; safety one correct, one wrong -> 0.5; overall 3/4
    answers = {"q1": ["A"], "q2": ["A"], "q3": ["A"], "q4": ["B"]}
    result = entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=applicant, answers=answers
    )
    assert result["score"] == 0.75
    assert result["profile"] == {"numeracy": 1.0, "safety": 0.5}
    assert result["level"] == "advanced"
    assert applicant.assessment_taken_at is not None
    assert applicant.assessment_level == "advanced"
    admin_session.rollback()


def test_level_bands():
    assert entrance_exam.level_for(0.0) == "beginner"
    assert entrance_exam.level_for(0.39) == "beginner"
    assert entrance_exam.level_for(0.4) == "intermediate"
    assert entrance_exam.level_for(0.69) == "intermediate"
    assert entrance_exam.level_for(0.7) == "advanced"
    assert entrance_exam.level_for(1.0) == "advanced"


def test_single_sitting(admin_session, tenant_a):
    bank = _bank_with_questions(admin_session, tenant_a)
    applicant = _applicant(admin_session, tenant_a, _cohort(admin_session, tenant_a, bank))
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=applicant, answers={"q1": ["A"]}
    )
    with pytest.raises(BadRequestError):
        entrance_exam.grade_and_record(
            admin_session, tenant_id=tenant_a.id, applicant=applicant, answers={"q1": ["A"]}
        )
    admin_session.rollback()


def test_requires_configured_bank(admin_session, tenant_a):
    applicant = _applicant(admin_session, tenant_a, _cohort(admin_session, tenant_a, bank=None))
    with pytest.raises(BadRequestError):
        entrance_exam.grade_and_record(admin_session, tenant_id=tenant_a.id, applicant=applicant, answers={})
    admin_session.rollback()


def test_completed_assessment_satisfies_onboarding_task(admin_session, tenant_a):
    bank = _bank_with_questions(admin_session, tenant_a)
    applicant = _applicant(admin_session, tenant_a, _cohort(admin_session, tenant_a, bank))
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=applicant,
        answers={"q1": ["A"], "q2": ["A"], "q3": ["A"], "q4": ["A"]},
    )
    for nxt in ("screened", "accepted", "onboarding"):
        admissions.transition_applicant(admin_session, applicant_id=applicant.id, to_status=nxt)
    tasks = onboarding.list_tasks(admin_session, tenant_id=tenant_a.id, applicant_id=applicant.id)
    entrance = next(t for t in tasks if t.key == "entrance_assessment")
    assert entrance.status == "done"
    admin_session.rollback()


def test_list_ranks_candidates_by_score(admin_session, tenant_a):
    bank = _bank_with_questions(admin_session, tenant_a)
    cohort = _cohort(admin_session, tenant_a, bank)
    high = _applicant(admin_session, tenant_a, cohort)
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=high,
        answers={"q1": ["A"], "q2": ["A"], "q3": ["A"], "q4": ["A"]},  # 1.0
    )
    low = _applicant(admin_session, tenant_a, cohort)
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=low,
        answers={"q1": ["A"], "q2": ["B"], "q3": ["B"], "q4": ["B"]},  # 0.25
    )
    ranked = admissions.list_applicants(admin_session, cohort_id=cohort.id, rank_by_score=True)
    assert [a.id for a in ranked] == [high.id, low.id]
    admin_session.rollback()


def _timed(admin_session, tenant, minutes=30):
    bank = _bank_with_questions(admin_session, tenant)
    cohort = _cohort(admin_session, tenant, bank)
    cohort.entrance_time_limit_minutes = minutes
    admin_session.flush()
    return _applicant(admin_session, tenant, cohort)


def test_start_exam_stamps_once_and_counts_down(admin_session, tenant_a):
    applicant = _timed(admin_session, tenant_a, minutes=30)
    t0 = datetime(2026, 7, 11, 10, 0, tzinfo=UTC)
    info = entrance_exam.start_exam(admin_session, applicant=applicant, now=t0)
    assert info["limit_minutes"] == 30 and info["remaining_seconds"] == 1800
    assert applicant.assessment_started_at == t0
    # re-opening 5 min later keeps counting from t0 (no reset)
    info2 = entrance_exam.start_exam(admin_session, applicant=applicant, now=t0 + timedelta(minutes=5))
    assert applicant.assessment_started_at == t0
    assert info2["remaining_seconds"] == 1500
    admin_session.rollback()


def test_grade_flags_time_exceeded(admin_session, tenant_a):
    applicant = _timed(admin_session, tenant_a, minutes=30)
    t0 = datetime(2026, 7, 11, 10, 0, tzinfo=UTC)
    entrance_exam.start_exam(admin_session, applicant=applicant, now=t0)
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=applicant,
        answers={"q1": ["A"]}, now=t0 + timedelta(minutes=40),
    )
    assert applicant.assessment_time_exceeded is True
    admin_session.rollback()


def test_grade_within_limit_not_exceeded(admin_session, tenant_a):
    applicant = _timed(admin_session, tenant_a, minutes=30)
    t0 = datetime(2026, 7, 11, 10, 0, tzinfo=UTC)
    entrance_exam.start_exam(admin_session, applicant=applicant, now=t0)
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=applicant,
        answers={"q1": ["A"]}, now=t0 + timedelta(minutes=20),
    )
    assert applicant.assessment_time_exceeded is False
    admin_session.rollback()


def test_untimed_cohort_never_exceeds(admin_session, tenant_a):
    bank = _bank_with_questions(admin_session, tenant_a)
    applicant = _applicant(admin_session, tenant_a, _cohort(admin_session, tenant_a, bank))
    info = entrance_exam.start_exam(admin_session, applicant=applicant)
    assert info["limit_minutes"] is None and info["remaining_seconds"] is None
    entrance_exam.grade_and_record(
        admin_session, tenant_id=tenant_a.id, applicant=applicant, answers={"q1": ["A"]}
    )
    assert applicant.assessment_time_exceeded is False
    admin_session.rollback()
