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


# ---------------------------------------------------------------------------
# Learner-side reporting (engagement, top movers, attention list)
# ---------------------------------------------------------------------------


def _mk_learner(admin_session, tenant, cohort, email, *, first="Lea", last="Rner", role="student"):
    from app.models.cohort import Enrollment
    from app.models.person import Person

    person = Person(tenant_id=tenant.id, email=email, first_name=first, last_name=last, status="active")
    admin_session.add(person)
    admin_session.flush()
    admin_session.add(
        Enrollment(
            tenant_id=tenant.id,
            cohort_id=cohort.id,
            person_id=person.id,
            role_in_cohort=role,
            status="active",
        )
    )
    admin_session.commit()
    return person


def _mk_cohort(admin_session, tenant, name="Report Cohort"):
    from app.models.cohort import Cohort

    cohort = Cohort(tenant_id=tenant.id, name=name, discipline="fiber", status="active")
    admin_session.add(cohort)
    admin_session.commit()
    return cohort


def _mk_events(admin_session, tenant, person, *, kind, n, occurred_at):
    from app.models.learning_event import LearningEvent

    admin_session.add_all(
        [
            LearningEvent(
                tenant_id=tenant.id,
                person_id=person.id,
                kind=kind,
                detail={},
                occurred_at=occurred_at,
            )
            for _ in range(n)
        ]
    )
    admin_session.commit()


def test_engagement_counts_roster_students_only(app_client, tenant_a, admin_session):
    from app.services.admin_reports import engagement_snapshot

    now = datetime.now(UTC)
    cohort = _mk_cohort(admin_session, tenant_a)
    busy = _mk_learner(admin_session, tenant_a, cohort, "busy@a.ex")
    stale = _mk_learner(admin_session, tenant_a, cohort, "stale@a.ex")
    _mk_learner(admin_session, tenant_a, cohort, "silent@a.ex")
    # An instructor with activity must not inflate the learner denominator.
    teacher = _mk_learner(admin_session, tenant_a, cohort, "teach2@a.ex", role="instructor")

    _mk_events(admin_session, tenant_a, busy, kind="chapter_viewed", n=2, occurred_at=now)
    _mk_events(admin_session, tenant_a, stale, kind="chapter_viewed", n=1, occurred_at=now - timedelta(days=10))
    _mk_events(admin_session, tenant_a, teacher, kind="chapter_viewed", n=5, occurred_at=now)

    eng = engagement_snapshot(admin_session, tenant_id=tenant_a.id, since=now - timedelta(hours=24))
    assert eng["enrollees"] == 3
    assert eng["ever_active"] == 2  # busy + stale
    assert eng["active_in_window"] == 1  # only busy
    assert eng["never_started"] == 1  # silent


def test_top_movers_ranked_with_submission_counts(app_client, tenant_a, admin_session):
    from app.services.admin_reports import top_movers

    now = datetime.now(UTC)
    cohort = _mk_cohort(admin_session, tenant_a, name="Movers")
    leader = _mk_learner(admin_session, tenant_a, cohort, "leader@a.ex", first="Lee", last="Der")
    runner = _mk_learner(admin_session, tenant_a, cohort, "runner@a.ex", first="Run", last="Ner")
    _mk_learner(admin_session, tenant_a, cohort, "absent@a.ex")

    _mk_events(admin_session, tenant_a, leader, kind="chapter_viewed", n=3, occurred_at=now)
    _mk_events(admin_session, tenant_a, leader, kind="submission_made", n=2, occurred_at=now)
    _mk_events(admin_session, tenant_a, runner, kind="chapter_viewed", n=1, occurred_at=now)
    # Outside the window: must not count towards the ranking.
    _mk_events(admin_session, tenant_a, runner, kind="chapter_viewed", n=9, occurred_at=now - timedelta(days=5))

    movers = top_movers(admin_session, tenant_id=tenant_a.id, since=now - timedelta(hours=24))
    assert [m["email"] for m in movers] == ["leader@a.ex", "runner@a.ex"]
    assert movers[0]["name"] == "Lee Der"
    assert movers[0]["events"] == 5
    assert movers[0]["submissions"] == 2
    assert movers[0]["cohort"] == "Movers"
    assert movers[1]["submissions"] == 0


def test_attention_list_reads_open_success_queue(app_client, tenant_a, admin_session):
    from app.models.success_queue import STATUS_RESOLVED, SuccessQueueEntry
    from app.services.admin_reports import attention_list

    now = datetime.now(UTC)
    cohort = _mk_cohort(admin_session, tenant_a, name="Attention")
    never = _mk_learner(admin_session, tenant_a, cohort, "never@a.ex", first="Nev", last="Er")
    quiet = _mk_learner(admin_session, tenant_a, cohort, "quiet@a.ex", first="Qui", last="Et")
    closed = _mk_learner(admin_session, tenant_a, cohort, "closed@a.ex")

    admin_session.add_all(
        [
            SuccessQueueEntry(
                tenant_id=tenant_a.id,
                person_id=never.id,
                cohort_id=cohort.id,
                reason_kind="inactivity",
                supporting_facts={"days_inactive": 30, "never_active": True},
                severity="high",
                detected_at=now,
            ),
            SuccessQueueEntry(
                tenant_id=tenant_a.id,
                person_id=quiet.id,
                cohort_id=cohort.id,
                reason_kind="below_passing",
                supporting_facts={},
                severity="medium",
                detected_at=now,
            ),
            SuccessQueueEntry(
                tenant_id=tenant_a.id,
                person_id=closed.id,
                cohort_id=cohort.id,
                reason_kind="inactivity",
                supporting_facts={"days_inactive": 9, "never_active": False},
                severity="medium",
                detected_at=now,
                status=STATUS_RESOLVED,
            ),
        ]
    )
    admin_session.commit()

    att = attention_list(admin_session, tenant_id=tenant_a.id)
    assert att["open_total"] == 2  # the resolved entry is not carried
    assert att["by_reason"] == {"inactivity": 1, "below_passing": 1}
    assert att["never_started"] == 1
    # Severity ordering is the queue's, not alphabetical: high before medium.
    assert att["top"][0]["email"] == "never@a.ex"
    assert att["top"][0]["reason"] == "inactive"
    assert att["top"][0]["days_inactive"] == 30
    assert att["top"][0]["never_active"] is True


def test_report_body_carries_learner_sections_and_escapes_names(app_client, tenant_a, admin_session):
    from app.models.success_queue import SuccessQueueEntry
    from app.services.admin_reports import _render, activity_snapshot

    now = datetime.now(UTC)
    cohort = _mk_cohort(admin_session, tenant_a, name="Bodies")
    mover = _mk_learner(admin_session, tenant_a, cohort, "mover@a.ex", first="<b>Evil", last="Name</b>")
    _mk_events(admin_session, tenant_a, mover, kind="chapter_viewed", n=2, occurred_at=now)
    admin_session.add(
        SuccessQueueEntry(
            tenant_id=tenant_a.id,
            person_id=mover.id,
            cohort_id=cohort.id,
            reason_kind="inactivity",
            supporting_facts={"days_inactive": 14, "never_active": False},
            severity="high",
            detected_at=now,
        )
    )
    admin_session.commit()

    snap = activity_snapshot(admin_session, tenant_id=tenant_a.id, since=now - timedelta(hours=24))
    html, text = _render(snap)

    assert "Top movers this window" in html and "Top movers this window" in text
    assert "Needs attention" in html and "Needs attention" in text
    assert "Never started" in text
    # Learner-supplied names are data, never markup.
    assert "<b>Evil" not in html
    assert "&lt;b&gt;Evil" in html
    assert "inactive 14d" in text
