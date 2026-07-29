"""Admin activity report — the daily email that keeps humans in the loop.

With admissions auto-progression live, no admin touches the pipeline day to
day; this report is the visibility that replaces them. One email per admin
per tenant summarising the reporting window (applications, sittings, auto
decisions, enrolments, learning activity) plus the current pipeline state.

Window metrics use the timestamps we actually have: applications by
``created_at``, sittings by ``assessment_taken_at``, auto decisions by the
policy's notes + ``updated_at``, enrolments/completions/submissions by their
rows' ``created_at``/``completed_at``. There is no per-transition history
table, so "auto-accepted this window" is an honest approximation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.admissions import Applicant
from app.models.assessment import Submission
from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.services.email import send_email


def _count(db: Session, stmt) -> int:
    return int(db.scalar(stmt) or 0)


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
    auto_accepted = _count(
        db,
        base.where(A.updated_at >= since)
        .where(A.notes.like("auto-accepted%"))
        .where(A.status.in_(("onboarding", "enrolled"))),
    )
    auto_waitlisted = _count(
        db,
        base.where(A.updated_at >= since).where(A.notes.like("auto-waitlisted%")).where(A.status == "waitlisted"),
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


def _render(snapshot: dict) -> tuple[str, str]:
    """(html, text) bodies for the report email."""
    s = snapshot
    avg = f"{s['avg_valid_score']:.0%}" if s["avg_valid_score"] is not None else "—"
    pipeline = ", ".join(f"{k}: {v}" for k, v in sorted(s["pipeline"].items())) or "empty"
    rows = [
        ("New applications", s["new_applications"]),
        ("Entrance sittings graded", f"{s['sittings']} ({s['sittings_valid']} valid, avg {avg})"),
        ("Auto-accepted", s["auto_accepted"]),
        ("Auto-waitlisted", s["auto_waitlisted"]),
        ("Invalid sittings awaiting review", s["invalid_awaiting_review"]),
        ("New enrolments", s["new_enrollments"]),
        ("Activity submissions", s["submissions"]),
        ("Course completions", s["completions"]),
    ]
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
        f"<p style='margin-top:16px;font-size:13px;color:#5B6B62;'>Pipeline now — {pipeline}</p>"
        "</div>"
    )
    text = (
        f"Dotmac Academy activity report (since {s['since']:%d %b %Y %H:%M} UTC)\n\n"
        + "\n".join(f"- {label}: {value}" for label, value in rows)
        + f"\n\nPipeline now: {pipeline}\n"
    )
    return html, text


def send_activity_report(db: Session, *, tenant_id: UUID, hours: int = 24) -> int:
    """Email the activity report to every tenant admin. Returns emails sent."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    snapshot = activity_snapshot(db, tenant_id=tenant_id, since=since)
    html, text = _render(snapshot)
    subject = f"Academy activity report — {datetime.now(UTC):%d %b %Y}"
    sent = 0
    for admin in admin_recipients(db, tenant_id=tenant_id):
        if send_email(admin.email, subject, html, text_body=text, db=db):
            sent += 1
    return sent
