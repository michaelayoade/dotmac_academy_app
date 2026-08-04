"""Admin activity report — the daily email that keeps humans in the loop.

With admissions auto-progression live, no admin touches the pipeline day to
day; this report is the visibility that replaces them. One email per admin
per tenant summarising the reporting window (applications, sittings, auto
decisions, enrolments, learning activity) plus the current pipeline state.

Window metrics use authoritative record timestamps. Automated admissions
decisions come from the audit transition ledger rather than mutable notes.

Learner-side reporting is a **read-only projection**, never a second opinion:
activity comes from the ``LearningEvent`` ledger, and who needs attention comes
from the open Success Queue exactly as ``services.success_queue`` decided it.
This module owns no rule and re-derives no threshold — if the queue is wrong,
it is wrong here too, which is the intended failure mode.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.admissions import Applicant
from app.models.assessment import Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.learning_event import KIND_SUBMISSION_MADE, LearningEvent
from app.models.person import Person
from app.models.rbac import AuditEvent, PersonRole, Role
from app.models.success_queue import REASON_INACTIVITY, STATUS_OPEN
from app.services import success_queue
from app.services.email_outbox import enqueue_email

# How many learners each learner-facing section names. The report is a daily
# nudge, not a roster dump — the admin UI is where the full lists live.
TOP_MOVERS_LIMIT = 5
ATTENTION_LIMIT = 8

# Reason kinds rendered with a human label; anything the Success Queue adds
# later still shows up, falling back to its slug.
_REASON_LABELS = {
    "inactivity": "inactive",
    "overdue_work": "overdue work",
    "below_passing": "below passing",
    "failed_final": "failed final",
    "certificate_blocked": "certificate blocked",
}


def _count(db: Session, stmt) -> int:
    return int(db.scalar(stmt) or 0)


def _name(person: Person) -> str:
    return f"{person.first_name} {person.last_name}".strip() or person.email


def _student_roster(tenant_id: UUID):
    """Subquery of person ids with an active student enrolment.

    Instructors and inactive enrolments are excluded so engagement rates are
    measured against the population the Academy actually expects to learn.
    """
    return (
        select(Enrollment.person_id)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.status == "active")
        .where(Enrollment.role_in_cohort == "student")
        .distinct()
    )


def engagement_snapshot(db: Session, *, tenant_id: UUID, since: datetime) -> dict:
    """Roster-wide engagement: of everyone enrolled, how many actually show up.

    ``never_started`` is the count with no ledger event *ever* — the number that
    stays invisible in window-only activity counts.
    """
    roster = _student_roster(tenant_id)
    enrollees = _count(db, select(func.count()).select_from(roster.subquery()))

    active = (
        select(func.count(func.distinct(LearningEvent.person_id)))
        .where(LearningEvent.tenant_id == tenant_id)
        .where(LearningEvent.person_id.in_(roster))
    )
    ever_active = _count(db, active)
    active_in_window = _count(db, active.where(LearningEvent.occurred_at >= since))

    return {
        "enrollees": enrollees,
        "ever_active": ever_active,
        "active_in_window": active_in_window,
        "never_started": max(enrollees - ever_active, 0),
    }


def top_movers(db: Session, *, tenant_id: UUID, since: datetime, limit: int = TOP_MOVERS_LIMIT) -> list[dict]:
    """The busiest learners in the window, richest activity first.

    Query count is fixed at four regardless of roster size: rank, then one
    bounded hydration each for people, cohorts and window grades.
    """
    ranked = db.execute(
        select(
            LearningEvent.person_id,
            func.count().label("events"),
            func.count().filter(LearningEvent.kind == KIND_SUBMISSION_MADE).label("submissions"),
            func.max(LearningEvent.occurred_at).label("last_seen"),
        )
        .where(LearningEvent.tenant_id == tenant_id)
        .where(LearningEvent.occurred_at >= since)
        .where(LearningEvent.person_id.in_(_student_roster(tenant_id)))
        .group_by(LearningEvent.person_id)
        .order_by(func.count().desc(), LearningEvent.person_id)
        .limit(limit)
    ).all()
    if not ranked:
        return []

    ids = [row.person_id for row in ranked]
    people = {
        p.id: p
        for p in db.scalars(select(Person).where(Person.tenant_id == tenant_id).where(Person.id.in_(ids)))
    }
    cohorts: dict[UUID, str] = {}
    for person_id, name in db.execute(
        select(Enrollment.person_id, Cohort.name)
        .join(Cohort, (Cohort.id == Enrollment.cohort_id) & (Cohort.tenant_id == Enrollment.tenant_id))
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.person_id.in_(ids))
        .where(Enrollment.status == "active")
        .order_by(Cohort.name)
    ).all():
        cohorts.setdefault(person_id, name)

    graded = {
        person_id: float(avg)
        for person_id, avg in db.execute(
            select(Submission.person_id, func.avg(Score.fraction))
            .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
            .where(Submission.tenant_id == tenant_id)
            .where(Submission.person_id.in_(ids))
            .where(Score.created_at >= since)
            .group_by(Submission.person_id)
        ).all()
        if avg is not None
    }

    out = []
    for row in ranked:
        person = people.get(row.person_id)
        if person is None:  # roster row without a person: skip rather than render a blank
            continue
        out.append(
            {
                "name": _name(person),
                "email": person.email,
                "cohort": cohorts.get(row.person_id, ""),
                "events": int(row.events),
                "submissions": int(row.submissions),
                "avg_score": graded.get(row.person_id),
            }
        )
    return out


def attention_list(db: Session, *, tenant_id: UUID, limit: int = ATTENTION_LIMIT) -> dict:
    """Who needs a human, straight from the open Success Queue.

    ``services.success_queue`` owns the rules and the severity; this reads its
    entries in the order it already ranks them and splits ``inactivity`` on the
    ``never_active`` fact it recorded, because "never logged in" and "went
    quiet" call for different outreach.
    """
    entries = success_queue.list_entries(db, tenant_id=tenant_id, status=STATUS_OPEN)

    by_reason: dict[str, int] = {}
    never_started = 0
    for item in entries:
        entry = item["entry"]
        by_reason[entry.reason_kind] = by_reason.get(entry.reason_kind, 0) + 1
        if entry.reason_kind == REASON_INACTIVITY and entry.supporting_facts.get("never_active"):
            never_started += 1

    top = []
    for item in entries[:limit]:
        entry, person = item["entry"], item["person"]
        facts = entry.supporting_facts
        top.append(
            {
                "name": _name(person),
                "email": person.email,
                "cohort": item["cohort_name"],
                "reason": _REASON_LABELS.get(entry.reason_kind, entry.reason_kind),
                "severity": entry.severity,
                "days_inactive": facts.get("days_inactive"),
                "never_active": bool(facts.get("never_active")),
            }
        )

    return {
        "open_total": len(entries),
        "by_reason": by_reason,
        "never_started": never_started,
        "top": top,
    }


def activity_snapshot(db: Session, *, tenant_id: UUID, since: datetime) -> dict:
    """Gather the window + pipeline numbers the report renders."""
    A = Applicant
    base = select(func.count()).select_from(A).where(A.tenant_id == tenant_id)

    new_applications = _count(db, base.where(A.created_at >= since))
    sittings = _count(db, base.where(A.assessment_taken_at >= since))
    sittings_valid = _count(db, base.where(A.assessment_taken_at >= since).where(A.assessment_valid.is_(True)))
    avg_score = db.scalar(
        select(func.avg(A.assessment_score))
        .where(A.tenant_id == tenant_id)
        .where(A.assessment_taken_at >= since)
        .where(A.assessment_valid.is_(True))
    )
    decision_events = (
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .where(AuditEvent.action == "applicant.transition")
        .where(AuditEvent.created_at >= since)
        .where(AuditEvent.details["source"].astext == "assessment_policy")
    )
    auto_accepted = _count(
        db,
        decision_events.where(AuditEvent.details["to_status"].astext == "onboarding"),
    )
    auto_waitlisted = _count(
        db,
        decision_events.where(AuditEvent.details["to_status"].astext == "waitlisted"),
    )
    invalid_awaiting = _count(
        db,
        base.where(A.status == "applied")
        .where(A.assessment_taken_at.is_not(None))
        .where(A.assessment_valid.is_not(True)),
    )

    pipeline_rows = db.execute(select(A.status, func.count()).where(A.tenant_id == tenant_id).group_by(A.status)).all()

    new_enrollments = _count(
        db,
        select(func.count())
        .select_from(Enrollment)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.created_at >= since),
    )
    submissions = _count(
        db,
        select(func.count())
        .select_from(Submission)
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.created_at >= since),
    )
    completions = _count(
        db,
        select(func.count())
        .select_from(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.completed_at >= since),
    )

    return {
        "since": since,
        "new_applications": new_applications,
        "sittings": sittings,
        "sittings_valid": sittings_valid,
        "avg_valid_score": float(avg_score) if avg_score is not None else None,
        "auto_accepted": auto_accepted,
        "auto_waitlisted": auto_waitlisted,
        "invalid_awaiting_review": invalid_awaiting,
        "pipeline": {status: n for status, n in pipeline_rows},
        "new_enrollments": new_enrollments,
        "submissions": submissions,
        "completions": completions,
        "engagement": engagement_snapshot(db, tenant_id=tenant_id, since=since),
        "top_movers": top_movers(db, tenant_id=tenant_id, since=since),
        "attention": attention_list(db, tenant_id=tenant_id),
    }


def admin_recipients(db: Session, *, tenant_id: UUID) -> list[Person]:
    """Active admin-role people with an email address."""
    return list(
        db.scalars(
            select(Person)
            .join(PersonRole, (PersonRole.person_id == Person.id) & (PersonRole.tenant_id == Person.tenant_id))
            .join(Role, (Role.id == PersonRole.role_id) & (Role.tenant_id == PersonRole.tenant_id))
            .where(Person.tenant_id == tenant_id)
            .where(Person.status == "active")
            .where(Role.slug == "admin")
            .where(Person.email.is_not(None))
        ).unique()
    )


def _mover_line(m: dict) -> str:
    """One top-mover as plain text: 'Name — 12 events, 4 submissions, avg 84% (Cohort)'."""
    bits = [f"{m['events']} events", f"{m['submissions']} submissions"]
    if m["avg_score"] is not None:
        bits.append(f"avg {m['avg_score']:.0%}")
    tail = f" ({m['cohort']})" if m["cohort"] else ""
    return f"{m['name']} — {', '.join(bits)}{tail}"


def _attention_line(a: dict) -> str:
    """One attention row: 'Name — inactive 21d, never started (Cohort)'."""
    reason = a["reason"]
    if a["days_inactive"] is not None:
        reason = f"{reason} {a['days_inactive']}d"
    if a["never_active"]:
        reason = f"{reason}, never started"
    tail = f" ({a['cohort']})" if a["cohort"] else ""
    return f"{a['name']} — {reason}{tail}"


def _render(snapshot: dict) -> tuple[str, str]:
    """(html, text) bodies for the report email."""
    s = snapshot
    avg = f"{s['avg_valid_score']:.0%}" if s["avg_valid_score"] is not None else "—"
    pipeline = ", ".join(f"{k}: {v}" for k, v in sorted(s["pipeline"].items())) or "empty"
    eng = s["engagement"]
    att = s["attention"]
    reasons = ", ".join(f"{k}: {v}" for k, v in sorted(att["by_reason"].items())) or "none"
    rows = [
        ("New applications", s["new_applications"]),
        ("Entrance sittings graded", f"{s['sittings']} ({s['sittings_valid']} valid, avg {avg})"),
        ("Auto-accepted", s["auto_accepted"]),
        ("Auto-waitlisted", s["auto_waitlisted"]),
        ("Invalid sittings awaiting review", s["invalid_awaiting_review"]),
        ("New enrolments", s["new_enrollments"]),
        ("Activity submissions", s["submissions"]),
        ("Course completions", s["completions"]),
        (
            "Learners active in window",
            f"{eng['active_in_window']} of {eng['enrollees']} enrolled",
        ),
        ("Never started (no activity ever)", eng["never_started"]),
        ("Open Success Queue items", f"{att['open_total']} ({reasons})"),
    ]
    movers = "".join(f"<li style='margin:2px 0;'>{escape(_mover_line(m))}</li>" for m in s["top_movers"])
    attention = "".join(f"<li style='margin:2px 0;'>{escape(_attention_line(a))}</li>" for a in att["top"])
    lists = ""
    if movers:
        lists += (
            "<h2 style='font-size:15px;margin:20px 0 6px;'>Top movers this window</h2>"
            f"<ul style='margin:0;padding-left:18px;font-size:13px;color:#0D1F16;'>{movers}</ul>"
        )
    if attention:
        remainder = att["open_total"] - len(att["top"])
        more = (
            f"<p style='margin:6px 0 0;font-size:12px;color:#5B6B62;'>+{remainder} more in the Success Queue</p>"
            if remainder > 0
            else ""
        )
        lists += (
            "<h2 style='font-size:15px;margin:20px 0 6px;'>Needs attention</h2>"
            f"<ul style='margin:0;padding-left:18px;font-size:13px;color:#0D1F16;'>{attention}</ul>{more}"
        )
    tr = "".join(
        f"<tr><td style='padding:6px 14px 6px 0;color:#5B6B62;'>{label}</td>"
        f"<td style='padding:6px 0;font-weight:600;'>{value}</td></tr>"
        for label, value in rows
    )
    html = (
        "<div style=\"font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#0D1F16;"
        'max-width:560px;margin:0 auto;padding:24px;">'
        "<p style='font-size:12px;letter-spacing:.14em;text-transform:uppercase;"
        "color:#0B4F31;font-weight:600;margin:0 0 4px;'>Dotmac Academy</p>"
        f"<h1 style='font-size:22px;margin:0 0 4px;'>Activity report</h1>"
        f"<p style='margin:0 0 16px;color:#5B6B62;font-size:13px;'>Since {s['since']:%d %b %Y %H:%M} UTC</p>"
        f"<table style='border-collapse:collapse;font-size:14px;'>{tr}</table>"
        f"{lists}"
        f"<p style='margin-top:16px;font-size:13px;color:#5B6B62;'>Pipeline now — {pipeline}</p>"
        "</div>"
    )
    text = (
        f"Dotmac Academy activity report (since {s['since']:%d %b %Y %H:%M} UTC)\n\n"
        + "\n".join(f"- {label}: {value}" for label, value in rows)
    )
    if s["top_movers"]:
        text += "\n\nTop movers this window:\n" + "\n".join(f"- {_mover_line(m)}" for m in s["top_movers"])
    if att["top"]:
        text += "\n\nNeeds attention:\n" + "\n".join(f"- {_attention_line(a)}" for a in att["top"])
        remainder = att["open_total"] - len(att["top"])
        if remainder > 0:
            text += f"\n- (+{remainder} more in the Success Queue)"
    text += f"\n\nPipeline now: {pipeline}\n"
    return html, text


def send_activity_report(db: Session, *, tenant_id: UUID, hours: int = 24) -> int:
    """Queue the activity report for every Academy admin."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    snapshot = activity_snapshot(db, tenant_id=tenant_id, since=since)
    html, text = _render(snapshot)
    subject = f"Academy activity report — {datetime.now(UTC):%d %b %Y}"
    sent = 0
    for admin in admin_recipients(db, tenant_id=tenant_id):
        if enqueue_email(
            db,
            tenant_id=tenant_id,
            idempotency_key=f"admin-report:{admin.id}:{datetime.now(UTC):%Y-%m-%d}:{hours}",
            kind="admin_report",
            recipient=admin.email,
            subject=subject,
            html_body=html,
            text_body=text,
        ):
            sent += 1
    return sent
