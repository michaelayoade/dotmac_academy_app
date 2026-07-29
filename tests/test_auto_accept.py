"""Auto-accept policy — graded entrance sitting → pipeline consequence.

Requires a migrated disposable Postgres (skipped otherwise by the fixtures).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.conftest import client_for


def _cohort(admin_session, tenant, threshold=None):
    from app.models.cohort import Cohort

    admin_session.rollback()
    c = Cohort(
        tenant_id=tenant.id,
        name=f"Intake-{threshold}",
        discipline="fiber",
        status="active",
        auto_accept_threshold=threshold,
    )
    admin_session.add(c)
    admin_session.commit()
    admin_session.refresh(c)
    return c


def _applicant(admin_session, tenant, cohort, email, *, score, valid, status="applied"):
    from app.models.admissions import Applicant

    admin_session.rollback()
    a = Applicant(
        tenant_id=tenant.id,
        email=email,
        first_name="Pol",
        last_name="Icy",
        status=status,
        cohort_id=cohort.id if cohort else None,
        assessment_score=score,
        assessment_valid=valid,
        assessment_taken_at=datetime.now(UTC) if score is not None else None,
    )
    admin_session.add(a)
    admin_session.commit()
    admin_session.refresh(a)
    return a


def _policy(admin_session, applicant):
    from app.services import admissions as admissions_service

    raw = admissions_service.apply_assessment_policy(admin_session, applicant=applicant)
    admin_session.commit()
    return raw


def test_valid_high_score_auto_accepts(app_client, tenant_a, admin_session):
    cohort = _cohort(admin_session, tenant_a, threshold=0.6)
    a = _applicant(admin_session, tenant_a, cohort, "hi@a.ex", score=0.8, valid=True)
    raw = _policy(admin_session, a)
    assert raw  # portal token returned for the offer email
    admin_session.refresh(a)
    assert a.status == "onboarding"
    assert "auto-accepted" in (a.notes or "")
    assert a.onboarding_token_hash
    # Checklist seeded, entrance task carried forward as done.
    rows = dict(
        admin_session.execute(
            text("SELECT key, status FROM onboarding_tasks WHERE applicant_id=:a"),
            {"a": str(a.id)},
        ).all()
    )
    assert rows.get("entrance_assessment") == "done"
    assert rows.get("confirm_details") == "pending"


def test_valid_low_score_waitlists(app_client, tenant_a, admin_session):
    cohort = _cohort(admin_session, tenant_a, threshold=0.6)
    a = _applicant(admin_session, tenant_a, cohort, "lo@a.ex", score=0.4, valid=True)
    assert _policy(admin_session, a) is None
    admin_session.refresh(a)
    assert a.status == "waitlisted"
    assert "auto-waitlisted" in (a.notes or "")


def test_invalid_sitting_left_for_humans(app_client, tenant_a, admin_session):
    cohort = _cohort(admin_session, tenant_a, threshold=0.6)
    a = _applicant(admin_session, tenant_a, cohort, "inv@a.ex", score=0.9, valid=False)
    assert _policy(admin_session, a) is None
    admin_session.refresh(a)
    assert a.status == "applied"


def test_no_threshold_means_no_auto_decision(app_client, tenant_a, admin_session):
    cohort = _cohort(admin_session, tenant_a, threshold=None)
    a = _applicant(admin_session, tenant_a, cohort, "off@a.ex", score=0.9, valid=True)
    assert _policy(admin_session, a) is None
    admin_session.refresh(a)
    assert a.status == "applied"


def test_non_applied_status_untouched(app_client, tenant_a, admin_session):
    cohort = _cohort(admin_session, tenant_a, threshold=0.6)
    a = _applicant(admin_session, tenant_a, cohort, "scr@a.ex", score=0.9, valid=True, status="screened")
    assert _policy(admin_session, a) is None
    admin_session.refresh(a)
    assert a.status == "screened"


def test_zero_admin_end_to_end(app_client, tenant_a, admin_session):
    """Auto-accept → portal checklist → enrolled student with an account invite,
    with no admin involved anywhere."""
    cohort = _cohort(admin_session, tenant_a, threshold=0.5)
    a = _applicant(admin_session, tenant_a, cohort, "e2e@a.ex", score=0.7, valid=True)
    raw = _policy(admin_session, a)
    assert raw

    web = client_for(TestClient(app_client.app), tenant_a.slug)
    r = web.get(f"/onboarding?token={raw}")
    assert r.status_code == 200 and "Confirm your details" in r.text
    # The GET set the csrf cookie; echo it as the double-submit header.
    csrf = {"x-csrf-token": web.cookies.get("csrf_token", "")}
    web.post("/onboarding/confirm", data={"token": raw}, headers=csrf)
    web.post("/onboarding/orientation", data={"token": raw}, headers=csrf)

    admin_session.rollback()
    row = admin_session.execute(text("SELECT status, person_id FROM applicants WHERE id=:a"), {"a": str(a.id)}).one()
    assert row.status == "enrolled"
    invites = admin_session.execute(
        text("SELECT count(*) FROM account_tokens WHERE person_id=:p AND kind='invite'"),
        {"p": str(row.person_id)},
    ).scalar()
    assert invites == 1
