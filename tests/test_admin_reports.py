"""Admin activity report — snapshot numbers and recipient selection.

Requires a migrated disposable Postgres (skipped otherwise by the fixtures).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _mk_applicant(admin_session, tenant, email, **kw):
    from app.models.admissions import Applicant

    a = Applicant(
        tenant_id=tenant.id,
        email=email,
        first_name="Rep",
        last_name="Ort",
        status=kw.pop("status", "applied"),
        **kw,
    )
    admin_session.add(a)
    admin_session.commit()
    return a


def test_snapshot_counts_window_activity(app_client, tenant_a, admin_session):
    from app.models.rbac import AuditEvent
    from app.services.admin_reports import activity_snapshot

    now = datetime.now(UTC)
    accepted = _mk_applicant(
        admin_session,
        tenant_a,
        "rep1@a.ex",
        status="onboarding",
        assessment_taken_at=now,
        assessment_score=0.9,
        assessment_valid=True,
    )
    waitlisted = _mk_applicant(
        admin_session,
        tenant_a,
        "rep2@a.ex",
        status="waitlisted",
        assessment_taken_at=now,
        assessment_score=0.3,
        assessment_valid=True,
    )
    _mk_applicant(
        admin_session,
        tenant_a,
        "rep3@a.ex",
        status="applied",
        assessment_taken_at=now,
        assessment_score=0.9,
        assessment_valid=False,
    )
    admin_session.add_all(
        [
            AuditEvent(
                tenant_id=tenant_a.id,
                action="applicant.transition",
                entity_type="applicant",
                entity_id=str(accepted.id),
                details={
                    "from_status": "applied",
                    "to_status": "onboarding",
                    "source": "assessment_policy",
                },
            ),
            AuditEvent(
                tenant_id=tenant_a.id,
                action="applicant.transition",
                entity_type="applicant",
                entity_id=str(waitlisted.id),
                details={
                    "from_status": "applied",
                    "to_status": "waitlisted",
                    "source": "assessment_policy",
                },
            ),
        ]
    )
    admin_session.commit()

    snap = activity_snapshot(admin_session, tenant_id=tenant_a.id, since=now - timedelta(hours=24))
    assert snap["new_applications"] == 3
    assert snap["sittings"] == 3
    assert snap["sittings_valid"] == 2
    assert snap["auto_accepted"] == 1
    assert snap["auto_waitlisted"] == 1
    assert snap["invalid_awaiting_review"] == 1
    assert snap["pipeline"]["applied"] == 1
    assert snap["pipeline"]["onboarding"] == 1

    # Outside the window nothing counts.
    old = activity_snapshot(admin_session, tenant_id=tenant_a.id, since=now + timedelta(hours=1))
    assert old["new_applications"] == 0
    assert old["sittings"] == 0
    # ...but the pipeline totals are still the current state.
    assert old["pipeline"]["applied"] == 1


def test_admin_recipients_only_active_admins(app_client, tenant_a, admin_session):
    from app.services.accounts import create_user
    from app.services.admin_reports import admin_recipients

    create_user(
        admin_session,
        tenant_id=tenant_a.id,
        email="boss@a.ex",
        first_name="Bo",
        last_name="Ss",
        password="correct horse battery staple",
        role="admin",
    )
    create_user(
        admin_session,
        tenant_id=tenant_a.id,
        email="teach@a.ex",
        first_name="Te",
        last_name="Ach",
        password="correct horse battery staple",
        role="instructor",
    )
    admin_session.commit()

    emails = {p.email for p in admin_recipients(admin_session, tenant_id=tenant_a.id)}
    assert "boss@a.ex" in emails
    assert "teach@a.ex" not in emails
