# app/services/entitlements.py
"""Course entitlement checks.

Single source of truth for "may this person study this course?". Access requires
an active Enrollment tying the person to a Cohort that has an active
CourseOffering for the course. Discipline strings do not grant access.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.course_access_request import CourseAccessRequest, REQUEST_STATUS_APPROVED
from app.models.offering import CourseOffering
from app.models.prerequisite import CoursePrerequisite
from app.models.track import TrackCourse


@dataclass(frozen=True)
class CourseAccessState:
    course_id: UUID
    locked: bool
    locked_reason: str | None = None
    locked_until_course_id: UUID | None = None


def _entitled_course_rows(db: Session, *, tenant_id: UUID, person_id: UUID):
    return db.execute(
        select(
            CourseOffering.course_id,
            Enrollment.track_id,
            TrackCourse.order_index,
            Course.title,
        )
        .distinct()
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id) & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .join(
            Course,
            (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .outerjoin(
            TrackCourse,
            (TrackCourse.tenant_id == Enrollment.tenant_id)
            & (TrackCourse.track_id == Enrollment.track_id)
            & (TrackCourse.course_id == CourseOffering.course_id),
        )
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(Course.status.in_(("published", "completed")))
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .where(or_(Enrollment.track_id.is_(None), TrackCourse.id.isnot(None)))
        .order_by(Enrollment.track_id, TrackCourse.order_index, Course.title)
    ).all()


def visible_course_ids(db: Session, *, tenant_id: UUID, person_id: UUID) -> set[UUID]:
    """Course ids the person is entitled to see, including locked track courses."""
    return {
        course_id
        for course_id, _track_id, _order_index, _title in _entitled_course_rows(
            db, tenant_id=tenant_id, person_id=person_id
        )
    }


def course_access_states(db: Session, *, tenant_id: UUID, person_id: UUID) -> dict[UUID, CourseAccessState]:
    """Access state for entitled courses.

    Track-assigned enrollments unlock courses in track order using the existing
    CourseCompletion.status == "completed" record for the immediately previous
    track course. Null-track enrollments preserve legacy cohort-wide access.
    """
    rows = _entitled_course_rows(db, tenant_id=tenant_id, person_id=person_id)
    if not rows:
        return {}

    approved_requests = set(
        db.scalars(
            select(CourseAccessRequest.course_id)
            .where(CourseAccessRequest.tenant_id == tenant_id)
            .where(CourseAccessRequest.person_id == person_id)
            .where(CourseAccessRequest.status == REQUEST_STATUS_APPROVED)
        ).all()
    )

    completed = set(
        db.scalars(
            select(CourseCompletion.course_id)
            .where(CourseCompletion.tenant_id == tenant_id)
            .where(CourseCompletion.person_id == person_id)
            .where(CourseCompletion.status == "completed")
        ).all()
    )

    track_sequences: dict[UUID, list[UUID]] = {}
    legacy_courses: set[UUID] = set()
    for course_id, track_id, _order_index, _title in rows:
        if track_id is None:
            legacy_courses.add(course_id)
            continue
        track_sequences.setdefault(track_id, [])
        if course_id not in track_sequences[track_id]:
            track_sequences[track_id].append(course_id)

    states: dict[UUID, CourseAccessState] = {
        course_id: CourseAccessState(course_id=course_id, locked=False) for course_id in legacy_courses
    }
    # Admin approvals are explicit overrides: the learner is treated as unlocked for
    # this course while the request remains approved.
    for course_id in approved_requests:
        if course_id in states:
            states[course_id] = CourseAccessState(course_id=course_id, locked=False)
    for sequence in track_sequences.values():
        for index, course_id in enumerate(sequence):
            if course_id in approved_requests:
                continue
            previous_course_id = sequence[index - 1] if index > 0 else None
            state = (
                CourseAccessState(course_id=course_id, locked=False)
                if previous_course_id is None or previous_course_id in completed
                else CourseAccessState(
                    course_id=course_id,
                    locked=True,
                    locked_reason="Complete the previous course to unlock this course.",
                    locked_until_course_id=previous_course_id,
                )
            )
            current = states.get(course_id)
            if current is None or current.locked:
                states[course_id] = state

    # Explicit CoursePrerequisite rules apply on top of track order: a course
    # with an uncompleted required course is locked even when track order (or a
    # null track) would otherwise open it. Without this, the dashboard shows
    # Start and the chapter route then 403s (require_course_open checks these).
    entitled_ids = [course_id for course_id, _t, _o, _title in rows]
    prereq_rows = db.execute(
        select(CoursePrerequisite.course_id, CoursePrerequisite.requires_course_id)
        .where(CoursePrerequisite.tenant_id == tenant_id)
        .where(CoursePrerequisite.course_id.in_(entitled_ids))
    ).all()
    for course_id, requires_course_id in prereq_rows:
        if requires_course_id in completed:
            continue
        if course_id in approved_requests:
            continue
        current = states.get(course_id)
        if current is not None and current.locked:
            continue  # already locked (track order); keep the first reason
        states[course_id] = CourseAccessState(
            course_id=course_id,
            locked=True,
            locked_reason="Complete the prerequisite course to unlock this course.",
            locked_until_course_id=requires_course_id,
        )
    return states


def accessible_course_ids(db: Session, *, tenant_id: UUID, person_id: UUID) -> set[UUID]:
    """Course ids the person may currently access/start."""
    return {
        course_id
        for course_id, state in course_access_states(db, tenant_id=tenant_id, person_id=person_id).items()
        if not state.locked
    }


def person_can_access_course(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID) -> bool:
    state = course_access_states(db, tenant_id=tenant_id, person_id=person_id).get(course_id)
    return bool(state and not state.locked)


def require_course_access(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID) -> None:
    """Raise 403 if the person is not entitled to the course."""
    if not person_can_access_course(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def open_course_ids(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> set[UUID]:
    """Entitled course ids whose offering window is currently open.

    A null window edge is open-ended; a fully null window is always open.
    """
    now = now or datetime.now(UTC)
    rows = db.scalars(
        select(CourseOffering.course_id)
        .distinct()
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id) & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .join(
            Course,
            (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .outerjoin(
            TrackCourse,
            (TrackCourse.tenant_id == Enrollment.tenant_id)
            & (TrackCourse.track_id == Enrollment.track_id)
            & (TrackCourse.course_id == CourseOffering.course_id),
        )
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(Course.status.in_(("published", "completed")))
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .where(or_(Enrollment.track_id.is_(None), TrackCourse.id.isnot(None)))
        .where(or_(CourseOffering.starts_at.is_(None), CourseOffering.starts_at <= now))
        .where(or_(CourseOffering.ends_at.is_(None), CourseOffering.ends_at >= now, Enrollment.access_ends_at >= now))
    ).all()
    return set(rows)


def unmet_prerequisites(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID) -> list[UUID]:
    """Prerequisite course ids the person has not yet completed."""
    required = list(
        db.scalars(
            select(CoursePrerequisite.requires_course_id)
            .where(CoursePrerequisite.tenant_id == tenant_id)
            .where(CoursePrerequisite.course_id == course_id)
        ).all()
    )
    state = course_access_states(db, tenant_id=tenant_id, person_id=person_id).get(course_id)
    if state is not None and state.locked and state.locked_until_course_id is not None:
        required.append(state.locked_until_course_id)
    if not required:
        return []
    completed = set(
        db.scalars(
            select(CourseCompletion.course_id)
            .where(CourseCompletion.tenant_id == tenant_id)
            .where(CourseCompletion.person_id == person_id)
            .where(CourseCompletion.status == "completed")
            .where(CourseCompletion.course_id.in_(set(required)))
        ).all()
    )
    return [cid for cid in required if cid not in completed]


def require_course_open(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    course_id: UUID,
    now: datetime | None = None,
) -> None:
    """Raise 403 if not entitled, the offering window isn't open, or a
    prerequisite course is not yet completed."""
    if course_id not in open_course_ids(db, tenant_id=tenant_id, person_id=person_id, now=now):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    if unmet_prerequisites(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Complete the previous course to unlock this course."
        )
