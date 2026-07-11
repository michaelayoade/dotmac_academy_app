"""Entrance assessment: grade an applicant's exam into a competency profile."""

from __future__ import annotations

import uuid

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
