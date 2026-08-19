"""Learner-initiated access request service.

Requests let a learner ask an admin to override a lock for a course.
Approved requests become explicit entitlements at the service layer used by all
access checks.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.course_access_request import (
    REQUEST_STATUS_APPROVED,
    REQUEST_STATUS_DENIED,
    REQUEST_STATUS_PENDING,
    REQUEST_STATUS_CANCELLED,
    REQUEST_STATUSES,
    CourseAccessRequest,
)
from app.models.person import Person
from app.services.exceptions import BadRequestError, ConflictError, NotFoundError


def status_by_courses(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_ids: list[UUID]
) -> dict[UUID, str]:
    """Current request status for one learner across a course list."""
    if not course_ids:
        return {}
    rows = db.execute(
        select(CourseAccessRequest.course_id, CourseAccessRequest.status)
        .where(CourseAccessRequest.tenant_id == tenant_id)
        .where(CourseAccessRequest.person_id == person_id)
        .where(CourseAccessRequest.course_id.in_(course_ids))
    ).all()
    return {course_id: status for course_id, status in rows}


def status_for_course(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID) -> str | None:
    """Return the request status for one course, or ``None`` if no request."""
    return db.scalar(
        select(CourseAccessRequest.status)
        .where(CourseAccessRequest.tenant_id == tenant_id)
        .where(CourseAccessRequest.person_id == person_id)
        .where(CourseAccessRequest.course_id == course_id)
    )


def list_requests(
    db: Session,
    *,
    tenant_id: UUID,
    status: str | None = None,
) -> list[dict]:
    """Administrative list of learner requests."""
    if status is not None and status not in REQUEST_STATUSES:
        raise BadRequestError("Unknown request status.")

    query = (
        select(CourseAccessRequest, Person, Course)
        .join(Person, (Person.id == CourseAccessRequest.person_id) & (Person.tenant_id == CourseAccessRequest.tenant_id))
        .join(Course, (Course.id == CourseAccessRequest.course_id) & (Course.tenant_id == CourseAccessRequest.tenant_id))
        .where(CourseAccessRequest.tenant_id == tenant_id)
        .order_by(CourseAccessRequest.created_at.desc())
    )
    if status is not None:
        query = query.where(CourseAccessRequest.status == status)

    out: list[dict] = []
    for req, person, course in db.execute(query).all():
        out.append(
            {
                "request": req,
                "person": person,
                "course": course,
                "requester_name": f"{person.first_name} {person.last_name}".strip(),
            }
        )
    return out


def status_counts(db: Session, *, tenant_id: UUID) -> dict[str, int]:
    """Count of each status for this tenant."""
    rows = db.execute(
        select(CourseAccessRequest.status, func.count().label("n"))
        .where(CourseAccessRequest.tenant_id == tenant_id)
        .group_by(CourseAccessRequest.status)
    ).all()
    counts = {status: 0 for status in REQUEST_STATUSES}
    for status, count in rows:
        counts[status] = int(count)
    return counts


def _request_for_course(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    course_id: UUID,
) -> CourseAccessRequest | None:
    return db.scalars(
        select(CourseAccessRequest)
        .where(CourseAccessRequest.tenant_id == tenant_id)
        .where(CourseAccessRequest.person_id == person_id)
        .where(CourseAccessRequest.course_id == course_id)
    ).first()


def create_or_reopen_request(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    course_id: UUID,
    requested_reason: str | None = None,
) -> CourseAccessRequest:
    """Create a request or reopen denied/cancelled records."""
    existing = _request_for_course(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    if existing is not None:
        if existing.status == REQUEST_STATUS_PENDING:
            raise ConflictError("A request is already pending for this course.")
        if existing.status == REQUEST_STATUS_APPROVED:
            return existing
        existing.status = REQUEST_STATUS_PENDING
        existing.requested_reason = requested_reason.strip() if requested_reason else None
        existing.reviewed_by_person_id = None
        existing.reviewed_at = None
        existing.reviewed_reason = None
        db.flush()
        return existing

    request = CourseAccessRequest(
        tenant_id=tenant_id,
        person_id=person_id,
        course_id=course_id,
        requested_reason=requested_reason.strip() if requested_reason else None,
    )
    db.add(request)
    db.flush()
    return request


def review_request(
    db: Session,
    *,
    tenant_id: UUID,
    request_id: UUID,
    status: str,
    reviewer_person_id: UUID,
    reviewed_reason: str | None = None,
) -> CourseAccessRequest:
    request = db.scalar(
        select(CourseAccessRequest)
        .where(CourseAccessRequest.tenant_id == tenant_id)
        .where(CourseAccessRequest.id == request_id)
    )
    if request is None:
        raise NotFoundError("Course access request not found.")
    if status not in {
        REQUEST_STATUS_APPROVED,
        REQUEST_STATUS_DENIED,
        REQUEST_STATUS_CANCELLED,
    }:
        raise BadRequestError("Invalid request status.")
    if request.status == status:
        return request

    request.status = status
    request.reviewed_by_person_id = reviewer_person_id
    request.reviewed_at = datetime.now(UTC)
    request.reviewed_reason = reviewed_reason.strip() if reviewed_reason else None
    db.flush()
    return request
