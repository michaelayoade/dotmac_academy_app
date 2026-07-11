"""Push academy course completions to dotmac_erp HR (training reports).

Best-effort: each completed course is a signed webhook to ERP, which records an
EmployeeCertification for staff learners (matched by work email) and ignores
everyone else. Inert unless ``erp_webhook_url`` is configured. ``erp_synced_at``
on the completion marks what's already been pushed so the sweep doesn't re-send.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.person import Person

logger = logging.getLogger(__name__)


def _sign(body: bytes) -> str:
    digest = hmac.new(settings.erp_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_payload(*, email: str, course_title: str, completed_on: datetime | None, certificate_ref: str) -> dict:
    """The `course_completed` event body ERP expects."""
    return {
        "event": "course_completed",
        "email": email,
        "course_title": course_title,
        "passed": True,
        "completed_on": completed_on.date().isoformat() if completed_on else None,
        "certificate_ref": certificate_ref,
    }


def push_completion(
    db: Session, *, tenant_id: UUID, completion: CourseCompletion, now: datetime | None = None
) -> bool:
    """Push one completion to ERP; stamp ``erp_synced_at`` on a 2xx. Returns success.

    Best-effort — never raises. On any failure the completion is left unsynced
    for the next sweep.
    """
    if not settings.erp_webhook_url:
        return False
    person = db.get(Person, completion.person_id)
    course = db.get(Course, completion.course_id)
    if person is None or course is None:
        return False

    payload = build_payload(
        email=person.email,
        course_title=course.title,
        completed_on=completion.completed_at,
        certificate_ref=str(completion.id),
    )
    body = json.dumps(payload).encode()
    try:
        resp = httpx.post(
            settings.erp_webhook_url,
            content=body,
            headers={"Content-Type": "application/json", "X-Webhook-Signature-256": _sign(body)},
            timeout=15.0,
        )
    except Exception as exc:  # network / timeout — leave unsynced, retry next sweep
        logger.warning("erp training push failed for completion %s: %s", completion.id, exc)
        return False
    if resp.status_code // 100 != 2:
        logger.warning("erp training push rejected (%s) for completion %s", resp.status_code, completion.id)
        return False

    completion.erp_synced_at = now or datetime.now(UTC)
    db.flush()
    return True


def sync_pending(db: Session, *, tenant_id: UUID, now: datetime | None = None) -> int:
    """Push every completed, not-yet-synced completion for a tenant. Returns count pushed."""
    if not settings.erp_webhook_url:
        return 0
    rows = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.status == "completed")
        .where(CourseCompletion.erp_synced_at.is_(None))
    ).all()
    pushed = 0
    for completion in rows:
        if push_completion(db, tenant_id=tenant_id, completion=completion, now=now):
            pushed += 1
    return pushed
