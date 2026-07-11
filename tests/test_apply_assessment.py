"""Public entrance-assessment flow: apply → tokenised exam → graded profile."""

from __future__ import annotations

import re
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.admissions import Applicant
from app.models.assessment import Question, QuestionBank
from app.models.cohort import Cohort
from app.models.course import Course
from tests.conftest import client_for


def _cohort_with_exam(admin_session, tenant):
    admin_session.rollback()
    course = Course(
        tenant_id=tenant.id, slug=f"c-{uuid.uuid4().hex[:6]}", title="Intake",
        discipline="fiber", source_ref="x", version=1,
    )
    admin_session.add(course)
    admin_session.commit()
    bank = QuestionBank(tenant_id=tenant.id, course_id=course.id, chapter_number=1, kind="chapter", version=1)
    admin_session.add(bank)
    admin_session.commit()
    for ext, cat in [("q1", "numeracy"), ("q2", "safety")]:
        admin_session.add(Question(
            tenant_id=tenant.id, bank_id=bank.id, ext_id=ext, stem="Pick A", type="single",
            options=["A", "B"], correct=["A"], rubric_category="recall", category=cat,
            explanation="", weight=1,
        ))
    cohort = Cohort(
        tenant_id=tenant.id, name="FA-Intake", discipline="fiber", status="active",
        entrance_bank_id=bank.id,
    )
    admin_session.add(cohort)
    admin_session.commit()
    admin_session.refresh(cohort)
    return cohort


def test_apply_offers_assessment_and_grades_profile(app_client, tenant_a, admin_session):
    cohort = _cohort_with_exam(admin_session, tenant_a)
    a = client_for(TestClient(app_client.app), tenant_a.slug)

    r = a.post(
        "/apply",
        data={"first_name": "Cand", "last_name": "Idate", "email": "cand@a.ex", "cohort_id": str(cohort.id)},
    )
    assert r.status_code == 200, r.text
    assert "Start the assessment" in r.text
    m = re.search(r"/apply/assessment\?token=([A-Za-z0-9_-]+)", r.text)
    assert m, r.text
    token = m.group(1)

    page = a.get(f"/apply/assessment?token={token}")
    assert page.status_code == 200
    assert "Pick A" in page.text

    csrf = a.cookies.get("csrf_token", "")
    sub = a.post(
        "/apply/assessment",
        data={"token": token, "q1": "A", "q2": "B"},  # q1 right, q2 wrong
        headers={"x-csrf-token": csrf},
    )
    assert sub.status_code == 200, sub.text
    assert "Assessment submitted" in sub.text

    admin_session.rollback()
    applicant = admin_session.scalars(
        select(Applicant).where(Applicant.email == "cand@a.ex")
    ).first()
    assert applicant is not None
    assert applicant.assessment_taken_at is not None
    assert applicant.assessment_score == 0.5
    assert applicant.assessment_profile == {"numeracy": 1.0, "safety": 0.0}


def test_bad_token_shows_notice(app_client, tenant_a):
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    r = a.get("/apply/assessment?token=not-a-real-token")
    assert r.status_code == 200
    assert "Link not valid" in r.text


def test_apply_without_open_cohort_just_thanks(app_client, tenant_a):
    a = client_for(TestClient(app_client.app), tenant_a.slug)
    r = a.post(
        "/apply",
        data={"first_name": "No", "last_name": "Exam", "email": "noexam@a.ex"},
    )
    assert r.status_code == 200, r.text
    assert "Application received" in r.text
    assert "Start the assessment" not in r.text
