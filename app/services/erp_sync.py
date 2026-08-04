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

# Payload contract version. ERP dispatches on it, so a future breaking change
# ships as version 2 alongside the old handler rather than as a silent reshape.
CONTRACT_VERSION = 1

# Push outcomes. UNMATCHED is deliberately not FAILED: retrying will not fix an
# identity mismatch, but it must not be mistaken for delivery either.
SYNCED = "synced"
UNMATCHED = "unmatched"
FAILED = "failed"


def _sign(body: bytes) -> str:
    digest = hmac.new(settings.erp_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_payload(*, email: str, course_title: str, completed_on: datetime | None, certificate_ref: str) -> dict:
    """The `course_completed` event body ERP expects."""
    return {
        "version": CONTRACT_VERSION,
        "event": "course_completed",
        "email": email,
        "course_title": course_title,
        "passed": True,
        "completed_on": completed_on.date().isoformat() if completed_on else None,
        "certificate_ref": certificate_ref,
    }


def _outcome(resp: httpx.Response) -> str:
    """Classify an ERP reply into SYNCED / UNMATCHED / FAILED.

    A 2xx alone is not delivery. ERP answers an unmatched employee with HTTP 200
    and ``{"status": "ignored"}``; treating that as success stamps
    ``erp_synced_at`` on a completion HR never received, and the completion is
    then never retried. The body decides, not the status line.
    """
    if resp.status_code // 100 != 2:
        return FAILED
    try:
        body = resp.json()
    except Exception:
        # A 2xx we cannot read is not evidence of anything. Retry rather than
        # assume; a permanently unreadable endpoint is a visible backlog.
        return FAILED
    if isinstance(body, dict) and str(body.get("status", "")).lower() == "ignored":
        return UNMATCHED
    return SYNCED


def push_completion(
    db: Session, *, tenant_id: UUID, completion: CourseCompletion, now: datetime | None = None
) -> str:
    """Push one completion to ERP. Returns SYNCED / UNMATCHED / FAILED.

    ``erp_synced_at`` is stamped only on SYNCED — an event ERP declined to
    record is not delivered, and leaving it unstamped keeps it in the backlog
    where it is visible and retried. Best-effort: never raises.
    """
    if not settings.erp_webhook_url:
        return FAILED
    person = db.get(Person, completion.person_id)
    course = db.get(Course, completion.course_id)
    if person is None or course is None:
        return FAILED

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
        return FAILED

    outcome = _outcome(resp)
    if outcome == UNMATCHED:
        # Named explicitly rather than folded into "failed": this one will not
        # fix itself by retrying, because the learner's Academy email does not
        # match any ERP employee. It needs the identity link corrected.
        logger.warning(
            "erp training push not recorded for completion %s: ERP matched no employee for %s",
            completion.id, person.email,
        )
        return UNMATCHED
    if outcome == FAILED:
        logger.warning(
            "erp training push rejected (%s) for completion %s", resp.status_code, completion.id
        )
        return FAILED

    completion.erp_synced_at = now or datetime.now(UTC)
    db.flush()
    return SYNCED


def sync_pending(db: Session, *, tenant_id: UUID, now: datetime | None = None) -> dict[str, int]:
    """Push every completed, not-yet-synced completion. Returns per-outcome counts.

    Counts are the point: a silent zero and a silent hundred-unmatched used to
    look identical from the outside.
    """
    counts = {SYNCED: 0, UNMATCHED: 0, FAILED: 0}
    if not settings.erp_webhook_url:
        return counts
    rows = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.status == "completed")
        .where(CourseCompletion.erp_synced_at.is_(None))
    ).all()
    for completion in rows:
        counts[push_completion(db, tenant_id=tenant_id, completion=completion, now=now)] += 1
    return counts
