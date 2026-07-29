"""Success Queue (roadmap P3b): explainable rules, idempotent sweep,
audited lifecycle, deterministic segments, message action, CSV reports."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.email_outbox import EmailOutbox
from app.models.offering import CourseOffering
from app.models.pacing import OfferingActivity
from app.models.person import Person
from app.models.success_queue import (
    REASON_INACTIVITY,
    REASON_OVERDUE_WORK,
    STATUS_OPEN,
    STATUS_RESOLVED,
    SuccessQueueEntry,
)
from app.services import csv_reports, success_queue
from app.services.audit import list_events


def _seed(admin_session, tenant, *, email, due_hours=None, enrolled_days_ago=30):
    person = Person(tenant_id=tenant.id, email=email, first_name="Sq", last_name="Learner")
    admin_session.add(person)
    cohort = Cohort(tenant_id=tenant.id, name=f"SQ Cohort {email}", discipline="fiber", status="active")
    admin_session.add(cohort)
    course = Course(tenant_id=tenant.id, slug=f"sq-{email.split('@')[0]}", title="SQ Course",
                    discipline="fiber", source_ref="t@1")
    admin_session.add(course)
    admin_session.flush()
    enr = Enrollment(tenant_id=tenant.id, cohort_id=cohort.id, person_id=person.id,
                     role_in_cohort="student", status="active")
    admin_session.add(enr)
    admin_session.flush()
    enr.created_at = datetime.now(UTC) - timedelta(days=enrolled_days_ago)
    off = CourseOffering(tenant_id=tenant.id, cohort_id=cohort.id, course_id=course.id, status="active")
    admin_session.add(off)
    admin_session.flush()
    act = None
    if due_hours is not None:
        act = Activity(tenant_id=tenant.id, course_id=course.id, chapter_number=1,
                       type="mcq_test", title="SQ act", pass_threshold=0.6)
        admin_session.add(act)
        admin_session.flush()
        admin_session.add(OfferingActivity(tenant_id=tenant.id, offering_id=off.id,
                                           activity_id=act.id,
                                           due_at=datetime.now(UTC) + timedelta(hours=due_hours)))
    admin_session.commit()
    return person, cohort, course, act


def _entries(db, tenant, person, reason=None):
    q = (select(SuccessQueueEntry)
         .where(SuccessQueueEntry.tenant_id == tenant.id)
         .where(SuccessQueueEntry.person_id == person.id))
    if reason:
        q = q.where(SuccessQueueEntry.reason_kind == reason)
    return db.scalars(q).all()


def test_inactivity_rule_fires_with_facts_and_refreshes_not_duplicates(admin_session, tenant_a):
    person, *_ = _seed(admin_session, tenant_a, email="inact@a.edu", enrolled_days_ago=20)
    now = datetime.now(UTC)
    success_queue.sweep(admin_session, tenant_id=tenant_a.id, now=now)
    success_queue.sweep(admin_session, tenant_id=tenant_a.id, now=now + timedelta(hours=1))
    admin_session.commit()
    rows = _entries(admin_session, tenant_a, person, REASON_INACTIVITY)
    assert len(rows) == 1
    entry = rows[0]
    assert entry.status == STATUS_OPEN
    assert entry.supporting_facts["days_inactive"] >= 14
    assert entry.supporting_facts["threshold_days"] == 7
    assert entry.severity == "high"  # 20 days >= 2x threshold
    assert entry.recommended_action


def test_overdue_rule_fires_and_auto_resolves_when_passed(admin_session, tenant_a):
    person, _, course, act = _seed(admin_session, tenant_a, email="ovd@a.edu", due_hours=-30)
    now = datetime.now(UTC)
    success_queue.sweep(admin_session, tenant_id=tenant_a.id, now=now)
    admin_session.commit()
    (entry,) = _entries(admin_session, tenant_a, person, REASON_OVERDUE_WORK)
    assert entry.supporting_facts["overdue_count"] == 1

    sub = Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=person.id, answers={}, attempt_no=1)
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tenant_a.id, submission_id=sub.id,
                            score=9, max_score=10, fraction=0.9, passed=True))
    admin_session.commit()
    success_queue.sweep(admin_session, tenant_id=tenant_a.id, now=now + timedelta(hours=1))
    admin_session.commit()
    (entry,) = _entries(admin_session, tenant_a, person, REASON_OVERDUE_WORK)
    assert entry.status == STATUS_RESOLVED
    assert entry.supporting_facts.get("auto_resolved")


def test_transitions_are_audited(admin_session, tenant_a):
    person, *_ = _seed(admin_session, tenant_a, email="trans@a.edu")
    actor = Person(tenant_id=tenant_a.id, email="staff@a.edu", first_name="St", last_name="Aff")
    admin_session.add(actor)
    admin_session.flush()
    success_queue.sweep(admin_session, tenant_id=tenant_a.id)
    admin_session.commit()
    (entry,) = _entries(admin_session, tenant_a, person, REASON_INACTIVITY)

    success_queue.transition(admin_session, tenant_id=tenant_a.id, entry_id=entry.id,
                             action="acknowledge", actor_person_id=actor.id)
    success_queue.transition(admin_session, tenant_id=tenant_a.id, entry_id=entry.id,
                             action="resolve", actor_person_id=actor.id)
    admin_session.commit()
    assert entry.status == STATUS_RESOLVED
    assert entry.resolved_by == actor.id
    actions = [e.action for e in list_events(admin_session, tenant_id=tenant_a.id, limit=20)]
    assert "success_queue.acknowledge" in actions
    assert "success_queue.resolve" in actions


def test_segment_membership_is_deterministic(admin_session, tenant_a):
    person, cohort, *_ = _seed(admin_session, tenant_a, email="seg@a.edu", enrolled_days_ago=15)
    members = success_queue.segment_members(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, segment="inactive")
    assert [m.id for m in members] == [person.id]
    again = success_queue.segment_members(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, segment="inactive")
    assert [m.id for m in again] == [person.id]
    none = success_queue.segment_members(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, segment="failed_final")
    assert none == []


def test_message_segment_enqueues_outbox_and_audits(admin_session, tenant_a):
    person, cohort, *_ = _seed(admin_session, tenant_a, email="msg@a.edu", enrolled_days_ago=15)
    actor = Person(tenant_id=tenant_a.id, email="coach@a.edu", first_name="Co", last_name="Ach")
    admin_session.add(actor)
    admin_session.flush()
    result = success_queue.message_segment(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id, segment="inactive",
        subject="Check in", body="How are you getting on?", actor_person_id=actor.id)
    admin_session.commit()
    assert result["recipients"] == 1
    rows = admin_session.scalars(
        select(EmailOutbox).where(EmailOutbox.tenant_id == tenant_a.id)
        .where(EmailOutbox.kind == "segment_message")).all()
    assert len(rows) == 1 and rows[0].recipient == person.email
    actions = [e.action for e in list_events(admin_session, tenant_id=tenant_a.id, limit=20)]
    assert "success_queue.message_segment" in actions


def test_csv_reports_content(admin_session, tenant_a):
    person, cohort, *_ = _seed(admin_session, tenant_a, email="csv@a.edu", enrolled_days_ago=15)
    success_queue.sweep(admin_session, tenant_id=tenant_a.id)
    admin_session.commit()

    name, text = csv_reports.cohort_roster_csv(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id)
    assert name.startswith("roster-progress-") and name.endswith(".csv")
    lines = text.strip().split("\r\n")
    assert lines[0].startswith("name,email,courses")
    assert any(person.email in line and "inactivity" in line for line in lines[1:])

    qname, qtext = csv_reports.queue_summary_csv(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id)
    qlines = qtext.strip().split("\r\n")
    assert qlines[0].startswith("name,email,cohort,reason")
    assert any("inactivity" in line for line in qlines[1:])

    fname, ftext = csv_reports.cohort_funnel_csv(
        admin_session, tenant_id=tenant_a.id, cohort_id=cohort.id)
    assert "enrolled,1" in ftext.replace("\r", "")
