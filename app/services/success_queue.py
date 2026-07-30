"""Explainable Success Queue + deterministic learner segments (roadmap P3b).

Single owner of intervention decisions. Every entry names the rule that fired
(``reason_kind``), carries the exact numbers behind it (``supporting_facts``),
a deterministic severity, and a recommended action — so an instructor sees
WHY, never just a flag. ``sweep`` is idempotent: an open entry is refreshed
in place, never duplicated; entries whose rule no longer holds are resolved
automatically with an audit trail.

Segments (item 22) reuse the same deterministic membership functions; the
message action is a thin adapter over the notifications service and the email
outbox — this module decides membership, never delivery.

No predictive ML (item 24): every derivation here is a stated rule over
canonical state and the learning-event ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from uuid import UUID, uuid4

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.certificate import Certificate
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.success_queue import (
    REASON_BELOW_PASSING,
    REASON_CERTIFICATE_BLOCKED,
    REASON_FAILED_FINAL,
    REASON_INACTIVITY,
    REASON_OVERDUE_WORK,
    STATUS_ACKNOWLEDGED,
    STATUS_OPEN,
    STATUS_RESOLVED,
    SuccessQueueEntry,
)
from app.services import learning_events, notifications
from app.services import todo as todo_service
from app.services.assessment import attempts_used, best_scores_for
from app.services.audit import write_audit_event
from app.services.email_outbox import enqueue_email
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.gradebook import course_grade
from app.services.settings_store import effective

# Deterministic severity thresholds (multipliers on the configured base).
_INACTIVITY_HIGH_FACTOR = 2  # inactive >= 2x threshold days -> high
_OVERDUE_HIGH_COUNT = 3

# Severity is stored as text but must sort highest-risk first, not alphabetically
# ("high" < "medium" < "low" as strings would surface medium ahead of high).
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def severity_order():
    """Descending severity ordering for ``SuccessQueueEntry`` queries — the one
    place the text-vs-rank mapping lives, shared by the queue view and the CSV."""
    return case(_SEVERITY_RANK, value=SuccessQueueEntry.severity, else_=0).desc()

SEGMENT_KEYS = (
    "inactive",
    "overdue_work",
    "below_passing",
    "failed_final",
    "almost_complete",
)
# Attendance-based segments arrive with roadmap P4; stated, not silently absent.
SEGMENTS_DEFERRED = ("low_attendance",)


# ---------------------------------------------------------------------------
# Rule evaluation — each returns None or (facts, severity, recommendation)
# ---------------------------------------------------------------------------


def _student_cohort_ids(db: Session, tenant_id: UUID, person_id: UUID) -> list[UUID]:
    return list(db.scalars(
        select(Enrollment.cohort_id)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.role_in_cohort == "student")
        .where(Enrollment.status == "active")
    ).all())


def _active_course_ids(db: Session, tenant_id: UUID, cohort_ids: list[UUID]) -> list[UUID]:
    if not cohort_ids:
        return []
    return list(db.scalars(
        select(CourseOffering.course_id)
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.cohort_id.in_(cohort_ids))
        .where(CourseOffering.status == "active")
    ).all())


def _rule_inactivity(db: Session, *, tenant_id: UUID, person_id: UUID,
                     enrolled_since: datetime | None, now: datetime,
                     threshold_days: int) -> tuple[dict, str, str] | None:
    last = learning_events.last_activity_at(db, tenant_id=tenant_id, person_id=person_id)
    anchor = last or enrolled_since
    if anchor is None:
        return None
    days = (now - anchor).days
    if days < threshold_days:
        return None
    severity = "high" if days >= threshold_days * _INACTIVITY_HIGH_FACTOR else "medium"
    facts = {
        "last_activity_at": anchor.isoformat(),
        "days_inactive": days,
        "threshold_days": threshold_days,
        "never_active": last is None,
    }
    action = "Reach out directly — a short call or message; ask what is blocking them."
    return facts, severity, action


def _rule_overdue(db: Session, *, tenant_id: UUID, person_id: UUID,
                  now: datetime) -> tuple[dict, str, str] | None:
    overdue = [r for r in todo_service._deadline_rows(db, tenant_id=tenant_id, person_id=person_id)
               if r["due_at"] < now]
    if not overdue:
        return None
    oldest = min(r["due_at"] for r in overdue)
    days_late = (now - oldest).days
    severity = "high" if len(overdue) >= _OVERDUE_HIGH_COUNT or days_late > 7 else "medium"
    facts = {
        "overdue_count": len(overdue),
        "oldest_due_at": oldest.isoformat(),
        "days_late": days_late,
        "titles": [r["activity"].title for r in overdue][:5],
    }
    action = "Agree a catch-up plan for the overdue work; consider a deadline extension."
    return facts, severity, action


def _rule_below_passing(db: Session, *, tenant_id: UUID, person_id: UUID,
                        course_ids: list[UUID], min_grade_pct: int) -> tuple[dict, str, str] | None:
    worst: dict | None = None
    for course_id in course_ids:
        grade = course_grade(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
        if not grade["per_activity"]:
            continue
        attempted = any(a["graded"] for a in grade["per_activity"])
        if not attempted:
            continue
        if grade["pct"] < min_grade_pct and (worst is None or grade["pct"] < worst["grade_pct"]):
            course = db.get(Course, course_id)
            worst = {
                "course_id": str(course_id),
                "course_title": course.title if course else "",
                "grade_pct": grade["pct"],
                "required_pct": min_grade_pct,
            }
    if worst is None:
        return None
    severity = "high" if worst["grade_pct"] < min_grade_pct // 2 else "medium"
    action = "Review their weakest activities together; point them at the relevant chapters."
    return worst, severity, action


def _rule_failed_final(db: Session, *, tenant_id: UUID, person_id: UUID,
                       course_ids: list[UUID]) -> tuple[dict, str, str] | None:
    if not course_ids:
        return None
    finals = db.scalars(
        select(Activity)
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id.in_(course_ids))
        .where(Activity.chapter_number.is_(None))
        .where(Activity.pass_threshold > 0)
    ).all()
    for final in finals:
        best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id,
                               course_id=final.course_id)
        score = best.get(final.id)
        if score is None or score.passed:
            continue
        used = attempts_used(db, tenant_id=tenant_id, person_id=person_id, activity_id=final.id)
        exhausted = final.max_attempts is not None and used >= final.max_attempts
        if not exhausted:
            continue
        course = db.get(Course, final.course_id)
        facts = {
            "course_id": str(final.course_id),
            "course_title": course.title if course else "",
            "activity_title": final.title,
            "best_pct": int(round(score.fraction * 100)),
            "required_pct": int(round(final.pass_threshold * 100)),
            "attempts_used": used,
            "max_attempts": final.max_attempts,
        }
        action = "Attempts exhausted on the final — review readiness and authorise a reset if warranted."
        return facts, "high", action
    return None


def _rule_certificate_blocked(db: Session, *, tenant_id: UUID, person_id: UUID
                              ) -> tuple[dict, str, str] | None:
    completions = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.status == "completed")
    ).all()
    for comp in completions:
        cert = db.scalars(
            select(Certificate)
            .where(Certificate.tenant_id == tenant_id)
            .where(Certificate.person_id == person_id)
            .where(Certificate.course_id == comp.course_id)
        ).first()
        if cert is not None:
            continue
        course = db.get(Course, comp.course_id)
        facts = {
            "course_id": str(comp.course_id),
            "course_title": course.title if course else "",
            "completion_pct": int(round(comp.pct * 100)),
            "missing": "certificate",
        }
        action = "Course is complete but no certificate exists — issue it or clear the blocker."
        return facts, "low", action
    return None


# ---------------------------------------------------------------------------
# Sweep — idempotent refresh of the queue
# ---------------------------------------------------------------------------


def _upsert(db: Session, *, tenant_id: UUID, person_id: UUID, cohort_id: UUID | None,
            reason: str, facts: dict, severity: str, action: str, now: datetime) -> str:
    entry = db.scalars(
        select(SuccessQueueEntry)
        .where(SuccessQueueEntry.tenant_id == tenant_id)
        .where(SuccessQueueEntry.person_id == person_id)
        .where(SuccessQueueEntry.reason_kind == reason)
        .where(SuccessQueueEntry.status.in_([STATUS_OPEN, STATUS_ACKNOWLEDGED]))
    ).first()
    if entry is not None:
        entry.supporting_facts = facts
        entry.severity = severity
        entry.detected_at = now
        entry.recommended_action = action
        entry.cohort_id = cohort_id
        db.flush()
        return "refreshed"
    db.add(SuccessQueueEntry(
        tenant_id=tenant_id, person_id=person_id, cohort_id=cohort_id,
        reason_kind=reason, supporting_facts=facts, severity=severity,
        detected_at=now, recommended_action=action, status=STATUS_OPEN,
    ))
    db.flush()
    return "opened"


def sweep(db: Session, *, tenant_id: UUID, now: datetime | None = None) -> dict:
    """Evaluate every rule for every active student; refresh the queue.

    Idempotent: open/acknowledged entries are refreshed, entries whose rule no
    longer fires are auto-resolved (actor None, noted in the audit trail).
    """
    now = now or datetime.now(UTC)
    cfg = effective(db)
    threshold_days = int(getattr(cfg, "success_inactive_days", 7) or 7)
    min_grade = int(getattr(cfg, "success_min_grade_pct", 60) or 60)

    counts = {"opened": 0, "refreshed": 0, "auto_resolved": 0}
    rows = db.execute(
        select(Enrollment.person_id, Enrollment.cohort_id, Enrollment.created_at)
        .join(Person, (Person.id == Enrollment.person_id) & (Person.tenant_id == Enrollment.tenant_id))
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.role_in_cohort == "student")
        .where(Enrollment.status == "active")
        # Suspended/offboarded people keep their enrolment rows; without this a
        # rule (e.g. inactivity) would hold an unresolvable entry for them
        # forever and segment messaging would email them.
        .where(Person.status == "active")
    ).all()
    primary_cohort: dict[UUID, UUID] = {}
    enrolled_since: dict[UUID, datetime] = {}
    for person_id, cohort_id, created_at in rows:
        primary_cohort.setdefault(person_id, cohort_id)
        anchor = created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC)
        if person_id not in enrolled_since or anchor < enrolled_since[person_id]:
            enrolled_since[person_id] = anchor

    for person_id in primary_cohort:
        cohort_ids = _student_cohort_ids(db, tenant_id, person_id)
        course_ids = _active_course_ids(db, tenant_id, cohort_ids)
        results = {
            REASON_INACTIVITY: _rule_inactivity(
                db, tenant_id=tenant_id, person_id=person_id,
                enrolled_since=enrolled_since.get(person_id), now=now,
                threshold_days=threshold_days),
            REASON_OVERDUE_WORK: _rule_overdue(
                db, tenant_id=tenant_id, person_id=person_id, now=now),
            REASON_BELOW_PASSING: _rule_below_passing(
                db, tenant_id=tenant_id, person_id=person_id,
                course_ids=course_ids, min_grade_pct=min_grade),
            REASON_FAILED_FINAL: _rule_failed_final(
                db, tenant_id=tenant_id, person_id=person_id, course_ids=course_ids),
            REASON_CERTIFICATE_BLOCKED: _rule_certificate_blocked(
                db, tenant_id=tenant_id, person_id=person_id),
        }
        for reason, result in results.items():
            if result is not None:
                facts, severity, action = result
                outcome = _upsert(db, tenant_id=tenant_id, person_id=person_id,
                                  cohort_id=primary_cohort[person_id], reason=reason,
                                  facts=facts, severity=severity, action=action, now=now)
                counts[outcome] += 1
            else:
                stale = db.scalars(
                    select(SuccessQueueEntry)
                    .where(SuccessQueueEntry.tenant_id == tenant_id)
                    .where(SuccessQueueEntry.person_id == person_id)
                    .where(SuccessQueueEntry.reason_kind == reason)
                    .where(SuccessQueueEntry.status.in_([STATUS_OPEN, STATUS_ACKNOWLEDGED]))
                ).first()
                if stale is not None:
                    stale.status = STATUS_RESOLVED
                    stale.resolved_at = now
                    stale.resolved_by = None
                    stale.supporting_facts = {**stale.supporting_facts,
                                              "auto_resolved": "rule no longer fires"}
                    counts["auto_resolved"] += 1
    db.flush()
    return counts


# ---------------------------------------------------------------------------
# Lifecycle transitions (instructor actions, audited)
# ---------------------------------------------------------------------------


def _get_entry(db: Session, tenant_id: UUID, entry_id: UUID) -> SuccessQueueEntry:
    entry = db.scalars(
        select(SuccessQueueEntry)
        .where(SuccessQueueEntry.tenant_id == tenant_id)
        .where(SuccessQueueEntry.id == entry_id)
    ).first()
    if entry is None:
        raise NotFoundError("queue entry not found")
    return entry


def transition(db: Session, *, tenant_id: UUID, entry_id: UUID, action: str,
               actor_person_id: UUID, assigned_to: UUID | None = None) -> SuccessQueueEntry:
    entry = _get_entry(db, tenant_id, entry_id)
    now = datetime.now(UTC)
    if action == "acknowledge" and entry.status == STATUS_OPEN:
        entry.status = STATUS_ACKNOWLEDGED
    elif action == "assign":
        entry.assigned_to = assigned_to or actor_person_id
        if entry.status == STATUS_OPEN:
            entry.status = STATUS_ACKNOWLEDGED
    elif action == "resolve" and entry.status in (STATUS_OPEN, STATUS_ACKNOWLEDGED):
        entry.status = STATUS_RESOLVED
        entry.resolved_at = now
        entry.resolved_by = actor_person_id
    else:
        raise BadRequestError(f"invalid transition {action!r} from {entry.status!r}")
    write_audit_event(db, tenant_id=tenant_id, actor_person_id=actor_person_id,
                      action=f"success_queue.{action}", entity_type="success_queue_entry",
                      entity_id=str(entry.id),
                      details={"reason": entry.reason_kind, "person_id": str(entry.person_id)})
    db.flush()
    return entry


def list_entries(db: Session, *, tenant_id: UUID, status: str | None = None,
                 severity: str | None = None, cohort_id: UUID | None = None) -> list[dict]:
    q = (
        select(SuccessQueueEntry, Person, Cohort.name)
        .join(Person, (Person.id == SuccessQueueEntry.person_id)
              & (Person.tenant_id == SuccessQueueEntry.tenant_id))
        .join(Cohort, (Cohort.id == SuccessQueueEntry.cohort_id)
              & (Cohort.tenant_id == SuccessQueueEntry.tenant_id), isouter=True)
        .where(SuccessQueueEntry.tenant_id == tenant_id)
        .order_by(severity_order(), SuccessQueueEntry.detected_at.desc())
    )
    if status:
        q = q.where(SuccessQueueEntry.status == status)
    if severity:
        q = q.where(SuccessQueueEntry.severity == severity)
    if cohort_id:
        q = q.where(SuccessQueueEntry.cohort_id == cohort_id)
    return [
        {"entry": entry, "person": person, "cohort_name": cohort_name or ""}
        for entry, person, cohort_name in db.execute(q).all()
    ]


# ---------------------------------------------------------------------------
# Deterministic segments + message action (item 22)
# ---------------------------------------------------------------------------


def segment_members(db: Session, *, tenant_id: UUID, cohort_id: UUID,
                    segment: str, now: datetime | None = None) -> list[Person]:
    """People in the cohort matching a deterministic segment rule."""
    now = now or datetime.now(UTC)
    if segment not in SEGMENT_KEYS:
        raise BadRequestError(f"unknown segment {segment!r}")
    cfg = effective(db)
    threshold_days = int(getattr(cfg, "success_inactive_days", 7) or 7)
    min_grade = int(getattr(cfg, "success_min_grade_pct", 60) or 60)

    people = db.scalars(
        select(Person)
        .join(Enrollment, (Enrollment.person_id == Person.id)
              & (Enrollment.tenant_id == Person.tenant_id))
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.role_in_cohort == "student")
        .where(Enrollment.status == "active")
        .where(Person.status == "active")
        .order_by(Person.last_name)
    ).all()

    members: list[Person] = []
    for person in people:
        cohort_ids = [cohort_id]
        course_ids = _active_course_ids(db, tenant_id, cohort_ids)
        if segment == "inactive":
            enrolled_since = db.scalar(
                select(func.min(Enrollment.created_at))
                .where(Enrollment.tenant_id == tenant_id)
                .where(Enrollment.person_id == person.id)
                .where(Enrollment.status == "active")
            )
            if enrolled_since is not None and enrolled_since.tzinfo is None:
                enrolled_since = enrolled_since.replace(tzinfo=UTC)
            hit = _rule_inactivity(db, tenant_id=tenant_id, person_id=person.id,
                                   enrolled_since=enrolled_since, now=now,
                                   threshold_days=threshold_days)
        elif segment == "overdue_work":
            hit = _rule_overdue(db, tenant_id=tenant_id, person_id=person.id, now=now)
        elif segment == "below_passing":
            hit = _rule_below_passing(db, tenant_id=tenant_id, person_id=person.id,
                                      course_ids=course_ids, min_grade_pct=min_grade)
        elif segment == "failed_final":
            hit = _rule_failed_final(db, tenant_id=tenant_id, person_id=person.id,
                                     course_ids=course_ids)
        else:  # almost_complete
            comp = db.scalars(
                select(CourseCompletion)
                .where(CourseCompletion.tenant_id == tenant_id)
                .where(CourseCompletion.person_id == person.id)
                .where(CourseCompletion.course_id.in_(course_ids or [uuid4()]))
                .where(CourseCompletion.pct >= 0.8)
                .where(CourseCompletion.status != "completed")
            ).first()
            hit = ({"pct": comp.pct}, "low", "") if comp is not None else None
        if hit is not None:
            members.append(person)
    return members


def message_segment(db: Session, *, tenant_id: UUID, cohort_id: UUID, segment: str,
                    subject: str, body: str, actor_person_id: UUID,
                    now: datetime | None = None) -> dict:
    """One audited action: in-app notification + outbox email per member."""
    subject = (subject or "").strip()
    body = (body or "").strip()
    if not subject or not body:
        raise BadRequestError("subject and message are both required")
    members = segment_members(db, tenant_id=tenant_id, cohort_id=cohort_id,
                              segment=segment, now=now)
    action_id = uuid4().hex[:12]
    # Free-form instructor input goes into email HTML — escape it so a stray
    # "<" can't break rendering or inject markup.
    html = "<p>" + escape(body).replace("\n", "<br>") + "</p>"
    for person in members:
        notifications.notify(db, tenant_id=tenant_id, person_id=person.id,
                             kind="instructor_message", title=subject, body=body, link="/")
        enqueue_email(
            db, tenant_id=tenant_id,
            idempotency_key=f"segmsg:{action_id}:{person.id}",
            kind="segment_message", recipient=person.email, subject=subject,
            html_body=html, text_body=body,
            payload={"segment": segment, "cohort_id": str(cohort_id)},
        )
    write_audit_event(db, tenant_id=tenant_id, actor_person_id=actor_person_id,
                      action="success_queue.message_segment", entity_type="cohort",
                      entity_id=str(cohort_id),
                      details={"segment": segment, "recipients": len(members),
                               "subject": subject, "action_id": action_id})
    db.flush()
    return {"recipients": len(members), "action_id": action_id}
