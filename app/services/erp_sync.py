"""Project staff course progress to dotmac_erp HR.

The hourly state-derived sweep sends changed percentages using the stable ERP
employee reference carried by a staff enrolment. Accepted snapshots advance
the persisted sync markers so unchanged state is not resent.
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
from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.offering import CourseOffering

logger = logging.getLogger(__name__)

# Payload contract version. ERP dispatches on it, so a future breaking change
# ships as version 2 alongside the old handler rather than as a silent reshape.
CONTRACT_VERSION = 2

# Push outcomes. UNMATCHED is deliberately not FAILED: retrying will not fix an
# identity mismatch, but it must not be mistaken for delivery either.
SYNCED = "synced"
UNMATCHED = "unmatched"
FAILED = "failed"


def _sign(body: bytes) -> str:
    digest = hmac.new(settings.erp_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_payload(
    *, enrollment: Enrollment, course: Course, completion: CourseCompletion
) -> dict:
    """Build the stable-identity v2 training projection ERP expects."""
    completed = completion.status == "completed"
    payload = {
        "version": CONTRACT_VERSION,
        "event": "course_completed" if completed else "training_progress_updated",
        "employee_ref": enrollment.employee_ref,
        "academy_enrollment_ref": str(enrollment.id),
        "academy_course_ref": course.source_ref,
        "course_title": course.title,
        "course_version": course.version,
        "progress_pct": round(completion.pct * 100, 2),
        "status": completion.status,
        "occurred_at": completion.updated_at.isoformat(),
    }
    if completed:
        payload.update(
            passed=True,
            completed_on=(
                completion.completed_at.date().isoformat()
                if completion.completed_at
                else None
            ),
            certificate_ref=str(completion.id),
        )
    return payload


# Reply bodies meaning "ERP understood us and wrote nothing".
_NOT_RECORDED = frozenset({"ignored", "unsupported"})
_RECORDED = frozenset({"recorded", "updated", "duplicate"})


def _reply_status(resp: httpx.Response) -> str | None:
    """The ``status`` field of an ERP reply, or None if unreadable.

    ERP returns this field on both success and refusal, at the top level of a
    2xx body and under ``detail`` in a 4xx error body.
    """
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    detail = body.get("detail")
    if isinstance(detail, dict) and "status" in detail:
        body = detail
    status = body.get("status")
    return str(status).lower() if status is not None else None


def _outcome(resp: httpx.Response) -> str:
    """Classify an ERP reply into SYNCED / UNMATCHED / FAILED.

    The body is read before the status line, deliberately. ERP historically
    answered an unmatched employee with HTTP 200 and ``{"status": "ignored"}``,
    and now answers 422 with the same status in ``detail`` — both mean the same
    thing, and both must classify as UNMATCHED rather than one being mistaken
    for delivery and the other for a transient failure worth retrying forever.
    """
    status = _reply_status(resp)
    if status in _NOT_RECORDED:
        return UNMATCHED
    if resp.status_code // 100 != 2:
        return FAILED
    if status not in _RECORDED:
        # A 2xx without an explicit acknowledgement is not evidence of a
        # durable write. Retry rather than silently discard the event.
        return FAILED
    return SYNCED


def push_completion(
    db: Session,
    *,
    tenant_id: UUID,
    completion: CourseCompletion,
    enrollment: Enrollment | None = None,
    now: datetime | None = None,
) -> str:
    """Push one completion to ERP. Returns SYNCED / UNMATCHED / FAILED.

    ``erp_synced_at`` is stamped only on SYNCED — an event ERP declined to
    record is not delivered, and leaving it unstamped keeps it in the backlog
    where it is visible and retried. Best-effort: never raises.
    """
    if not settings.erp_webhook_url:
        return FAILED
    course = db.get(Course, completion.course_id)
    if enrollment is None:
        enrollment = db.scalar(
            select(Enrollment)
            .join(
                CourseOffering,
                (CourseOffering.tenant_id == Enrollment.tenant_id)
                & (CourseOffering.cohort_id == Enrollment.cohort_id),
            )
            .where(
                Enrollment.tenant_id == tenant_id,
                Enrollment.person_id == completion.person_id,
                Enrollment.audience == "staff",
                Enrollment.employee_ref.is_not(None),
                CourseOffering.course_id == completion.course_id,
                CourseOffering.status == "active",
            )
        )
    if enrollment is None or course is None:
        return FAILED

    payload = build_payload(enrollment=enrollment, course=course, completion=completion)
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
            completion.id, enrollment.employee_ref,
        )
        return UNMATCHED
    if outcome == FAILED:
        logger.warning(
            "erp training push rejected (%s) for completion %s", resp.status_code, completion.id
        )
        return FAILED

    completion.erp_synced_pct = completion.pct
    if completion.status == "completed":
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
    rows = db.execute(
        select(CourseCompletion, Enrollment)
        .join(
            CourseOffering,
            (CourseOffering.tenant_id == CourseCompletion.tenant_id)
            & (CourseOffering.course_id == CourseCompletion.course_id),
        )
        .join(
            Enrollment,
            (Enrollment.tenant_id == CourseOffering.tenant_id)
            & (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.person_id == CourseCompletion.person_id),
        )
        .where(
            CourseCompletion.tenant_id == tenant_id,
            Enrollment.audience == "staff",
            Enrollment.employee_ref.is_not(None),
            Enrollment.status == "active",
            CourseOffering.status == "active",
        )
    ).all()
    seen: set[UUID] = set()
    for completion, enrollment in rows:
        if completion.id in seen or completion.erp_synced_pct == completion.pct:
            continue
        seen.add(completion.id)
        outcome = push_completion(
            db,
            tenant_id=tenant_id,
            completion=completion,
            enrollment=enrollment,
            now=now,
        )
        counts[outcome] += 1
    from app.services import erp_assessment_sync

    for outcome, amount in erp_assessment_sync.sync_pending(
        db, tenant_id=tenant_id, now=now
    ).items():
        counts[outcome] += amount
    return counts
