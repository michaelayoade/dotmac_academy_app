# app/services/completion.py
"""Course completion recomputation.

Completion = fraction of a course's activities with a passing best score. The
single per-(person, course) ``CourseCompletion`` record is upserted on every
score write; ``completed_at`` is stamped once, the first time pct reaches 1.0.
"""

from __future__ import annotations

import html
import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.person import Person
from app.services.assessment import best_scores_for

logger = logging.getLogger(__name__)


def recompute_completion(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    course_id: UUID,
    now: datetime | None = None,
) -> CourseCompletion:
    """Upsert the person's completion record for the course and return it."""
    db.execute(
        select(Person.id)
        .where(Person.tenant_id == tenant_id)
        .where(Person.id == person_id)
        .with_for_update()
    )
    total = (
        db.scalar(
            select(func.count())
            .select_from(Activity)
            .where(Activity.tenant_id == tenant_id)
            .where(Activity.course_id == course_id)
        )
        or 0
    )
    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    passed = sum(1 for s in best.values() if s.passed)
    pct = (passed / total) if total else 0.0
    is_complete = total > 0 and passed == total

    rec = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.course_id == course_id)
    ).first()
    if rec is None:
        rec = CourseCompletion(tenant_id=tenant_id, person_id=person_id, course_id=course_id)
        db.add(rec)

    first_completion = is_complete and rec.completed_at is None
    rec.pct = pct
    if is_complete:
        rec.status = "completed"
        if rec.completed_at is None:  # stamp once
            rec.completed_at = now or datetime.now(UTC)
    else:
        rec.status = "in_progress"
        rec.completed_at = None
    db.flush()
    if first_completion:
        course = db.scalars(select(Course).where(Course.tenant_id == tenant_id).where(Course.id == course_id)).first()
        course_title = course.title if course is not None else "the course"
        # Issue the certificate RECORD + serial immediately on completion,
        # independent of the email path (which is skipped for opted-out or
        # email-less learners). The PDF still renders lazily on download.
        # Without this, a completed course shows a permanent certificate_blocked.
        try:
            from app.services.certificates import issue_certificate

            issue_certificate(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id, now=now)
        except Exception as exc:
            logger.warning("certificate issuance on completion failed: %s", exc)
        try:
            from app.services.notifications import notify

            notify(
                db,
                tenant_id=tenant_id,
                person_id=person_id,
                kind="course_completed",
                title="Well done, course completed",
                body=f"Congratulations on completing {course_title}.",
                link=f"/certificates/{course_id}",
            )
        except Exception as exc:
            logger.warning("course completion notification failed: %s", exc)
        try:
            _email_certificate(
                db, tenant_id=tenant_id, person_id=person_id, course_id=course_id, course_title=course_title
            )
        except Exception as exc:
            logger.warning("course completion certificate email failed: %s", exc)
    return rec


def _email_certificate(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID, course_title: str) -> bool:
    """Queue the freshly-completed course's certificate email.

    The certificate and outbox intent commit atomically. The delivery worker
    renders the PDF after commit and retries SMTP independently.
    """
    from app.models.person import Person
    from app.services.certificates import issue_certificate
    from app.services.email import recipient_allows
    from app.services.email_outbox import enqueue_email

    person = db.get(Person, person_id)
    if person is None or not person.email:
        return False
    if not recipient_allows(person, "email_results"):
        return False

    cert = issue_certificate(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    name_text = person.first_name or "there"
    name = html.escape(name_text)
    safe_title = html.escape(course_title)
    html_body = (
        "<div style=\"font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#0D1F16;"
        'max-width:560px;margin:0 auto;padding:24px;">'
        "<p style='font-size:12px;letter-spacing:.14em;text-transform:uppercase;"
        "color:#0B4F31;font-weight:600;margin:0 0 4px;'>Dotmac Academy</p>"
        f"<h1 style='font-size:22px;margin:0 0 16px;'>Congratulations, {name}!</h1>"
        f"<p>You've completed <strong>{safe_title}</strong>. Your certificate is attached.</p>"
        f"<p style='font-size:13px;color:#5B6B62;'>Certificate serial: {cert.serial}. You can also "
        "download it any time from your course page.</p></div>"
    )
    text = (
        f"Congratulations, {name_text}!\n\nYou've completed {course_title}. "
        f"Your certificate is attached (serial {cert.serial}).\n"
    )
    return enqueue_email(
        db,
        tenant_id=tenant_id,
        idempotency_key=f"certificate:{cert.id}",
        kind="certificate",
        recipient=person.email,
        subject=f"Your certificate — {course_title}",
        html_body=html_body,
        text_body=text,
        payload={"person_id": str(person_id), "course_id": str(course_id)},
    )
