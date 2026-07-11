"""At-risk / behind-pace detection + learner nudges.

Complements the agenda (which shows what's *upcoming*) by flagging what a
learner is *behind on*: a course whose offering window has closed without
completion (**overdue**), or where progress lags the elapsed window
(**behind**). Surfaced as in-app notifications via a daily sweep, mirroring
the email-digest job.

Signal uses only ``CourseCompletion.pct``/``status`` + the offering window, so
it needs no per-activity plumbing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.notification import Notification
from app.models.offering import CourseOffering
from app.services import notifications

# How far progress may lag the elapsed window before a learner is "behind".
DEFAULT_BEHIND_THRESHOLD = 0.2


def at_risk_for_person(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    behind_threshold: float = DEFAULT_BEHIND_THRESHOLD,
    now: datetime | None = None,
) -> list[dict]:
    """Return the person's at-risk courses: [{course_id, title, reason, pct, expected}]."""
    now = now or datetime.now(UTC)

    cohort_ids = list(
        db.scalars(
            select(Enrollment.cohort_id)
            .where(Enrollment.tenant_id == tenant_id)
            .where(Enrollment.person_id == person_id)
            .where(Enrollment.role_in_cohort == "student")
        ).all()
    )
    if not cohort_ids:
        return []

    offerings = db.scalars(
        select(CourseOffering)
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(CourseOffering.cohort_id.in_(cohort_ids))
    ).all()
    if not offerings:
        return []

    completions = {
        c.course_id: c
        for c in db.scalars(
            select(CourseCompletion)
            .where(CourseCompletion.tenant_id == tenant_id)
            .where(CourseCompletion.person_id == person_id)
        ).all()
    }
    course_ids = {o.course_id for o in offerings}
    titles = {
        c.id: c.title
        for c in db.scalars(select(Course).where(Course.tenant_id == tenant_id).where(Course.id.in_(course_ids))).all()
    }

    results: list[dict] = []
    for off in offerings:
        comp = completions.get(off.course_id)
        pct = comp.pct if comp else 0.0
        if comp is not None and comp.status == "completed":
            continue

        if off.ends_at is not None and off.ends_at < now:
            results.append(
                {
                    "course_id": off.course_id,
                    "title": titles.get(off.course_id, "your course"),
                    "reason": "overdue",
                    "pct": pct,
                    "expected": 1.0,
                }
            )
            continue

        if off.starts_at is not None and off.ends_at is not None and off.starts_at < now < off.ends_at:
            span = (off.ends_at - off.starts_at).total_seconds()
            elapsed = (now - off.starts_at).total_seconds() / span if span > 0 else 0.0
            if pct < elapsed - behind_threshold:
                results.append(
                    {
                        "course_id": off.course_id,
                        "title": titles.get(off.course_id, "your course"),
                        "reason": "behind",
                        "pct": pct,
                        "expected": elapsed,
                    }
                )

    return results


def notify_person_if_at_risk(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> int:
    """Send one in-app nudge per at-risk course. Returns how many were sent.

    Deduped: skips a course that already has an unread at-risk nudge, so a
    daily sweep doesn't spam.
    """
    existing = set(
        db.scalars(
            select(Notification.link)
            .where(Notification.tenant_id == tenant_id)
            .where(Notification.person_id == person_id)
            .where(Notification.kind == "at_risk")
            .where(Notification.read_at.is_(None))
        ).all()
    )
    sent = 0
    for item in at_risk_for_person(db, tenant_id=tenant_id, person_id=person_id, now=now):
        link = f"/courses/{item['course_id']}"
        if link in existing:
            continue
        if item["reason"] == "overdue":
            title = f"Overdue: {item['title']}"
            body = "This course's window has closed and you haven't completed it yet."
        else:
            title = f"You're behind on {item['title']}"
            body = (
                f"You're at {round(item['pct'] * 100)}% but should be near "
                f"{round(item['expected'] * 100)}% by now. Catch up when you can."
            )
        notifications.notify(
            db,
            tenant_id=tenant_id,
            person_id=person_id,
            kind="at_risk",
            title=title,
            body=body,
            link=link,
        )
        sent += 1
    return sent
