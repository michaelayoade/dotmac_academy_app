# app/services/tracks.py
"""Track management helpers.

Tracks are an additive curriculum layer above the existing CourseOffering
entitlement table. CourseOffering remains the coarse cohort/course availability
record; a non-null Enrollment.track_id narrows a learner to that track's courses.
"""

from __future__ import annotations

import re
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.track import CohortTrack, Track, TrackCourse
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.lookups import cohort_or_404


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return slug or "track"


def _unique_track_slug(db: Session, *, tenant_id: UUID, name: str) -> str:
    base = _slugify(name)[:70]
    slug = base
    i = 2
    while db.scalars(select(Track).where(Track.tenant_id == tenant_id).where(Track.slug == slug)).first():
        suffix = f"-{i}"
        slug = f"{base[:80 - len(suffix)]}{suffix}"
        i += 1
    return slug


def list_cohort_tracks(db: Session, *, tenant_id: UUID, cohort_id: UUID) -> list[dict]:
    cohort_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id)
    rows = db.execute(
        select(CohortTrack, Track)
        .join(Track, (Track.id == CohortTrack.track_id) & (Track.tenant_id == CohortTrack.tenant_id))
        .where(CohortTrack.tenant_id == tenant_id)
        .where(CohortTrack.cohort_id == cohort_id)
        .where(CohortTrack.status == "active")
        .order_by(Track.name)
    ).all()
    out: list[dict] = []
    for cohort_track, track in rows:
        courses = db.scalars(
            select(Course)
            .join(TrackCourse, (TrackCourse.course_id == Course.id) & (TrackCourse.tenant_id == Course.tenant_id))
            .where(TrackCourse.tenant_id == tenant_id)
            .where(TrackCourse.track_id == track.id)
            .order_by(TrackCourse.order_index, Course.title)
        ).all()
        out.append({"cohort_track": cohort_track, "track": track, "courses": list(courses)})
    return out


def tracks_for_cohorts(db: Session, *, tenant_id: UUID, cohort_ids: list[UUID]) -> dict[UUID, list[Track]]:
    if not cohort_ids:
        return {}
    rows = db.execute(
        select(CohortTrack.cohort_id, Track)
        .join(Track, (Track.id == CohortTrack.track_id) & (Track.tenant_id == CohortTrack.tenant_id))
        .where(CohortTrack.tenant_id == tenant_id)
        .where(CohortTrack.cohort_id.in_(cohort_ids))
        .where(CohortTrack.status == "active")
        .where(Track.status == "active")
        .order_by(Track.name)
    ).all()
    grouped: dict[UUID, list[Track]] = {cohort_id: [] for cohort_id in cohort_ids}
    for cohort_id, track in rows:
        grouped.setdefault(cohort_id, []).append(track)
    return grouped


def create_cohort_track(
    db: Session,
    *,
    tenant_id: UUID,
    cohort_id: UUID,
    name: str,
    course_ids: list[UUID],
) -> Track:
    cohort_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id)
    clean_name = (name or "").strip()
    if not clean_name:
        raise BadRequestError("track name is required")
    if not course_ids:
        raise BadRequestError("select at least one course")

    seen: list[UUID] = []
    for course_id in course_ids:
        if course_id not in seen:
            seen.append(course_id)
    courses = db.scalars(select(Course).where(Course.tenant_id == tenant_id).where(Course.id.in_(seen))).all()
    found = {course.id for course in courses}
    if found != set(seen):
        raise NotFoundError("one or more courses were not found")

    track = Track(
        tenant_id=tenant_id,
        slug=_unique_track_slug(db, tenant_id=tenant_id, name=clean_name),
        name=clean_name,
    )
    db.add(track)
    db.flush()
    db.add(CohortTrack(tenant_id=tenant_id, cohort_id=cohort_id, track_id=track.id, status="active"))
    for idx, course_id in enumerate(seen, start=1):
        db.add(TrackCourse(tenant_id=tenant_id, track_id=track.id, course_id=course_id, order_index=idx))
    db.flush()
    ensure_track_offerings(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track.id)
    return track


def add_courses_to_cohort_track(
    db: Session,
    *,
    tenant_id: UUID,
    cohort_id: UUID,
    track_id: UUID,
    course_ids: list[UUID],
) -> Track:
    cohort_track_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track_id)
    if not course_ids:
        raise BadRequestError("select at least one course")

    seen: list[UUID] = []
    for course_id in course_ids:
        if course_id not in seen:
            seen.append(course_id)
    courses = db.scalars(select(Course).where(Course.tenant_id == tenant_id).where(Course.id.in_(seen))).all()
    found = {course.id for course in courses}
    if found != set(seen):
        raise NotFoundError("one or more courses were not found")

    existing = set(
        db.scalars(
            select(TrackCourse.course_id)
            .where(TrackCourse.tenant_id == tenant_id)
            .where(TrackCourse.track_id == track_id)
        ).all()
    )
    max_order = (
        db.scalar(
            select(TrackCourse.order_index)
            .where(TrackCourse.tenant_id == tenant_id)
            .where(TrackCourse.track_id == track_id)
            .order_by(TrackCourse.order_index.desc())
            .limit(1)
        )
        or 0
    )
    next_order = max_order + 1
    for course_id in seen:
        if course_id in existing:
            continue
        db.add(
            TrackCourse(
                tenant_id=tenant_id,
                track_id=track_id,
                course_id=course_id,
                order_index=next_order,
            )
        )
        next_order += 1
    db.flush()
    ensure_track_offerings(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track_id)
    track = db.scalars(select(Track).where(Track.tenant_id == tenant_id).where(Track.id == track_id)).first()
    if track is None:
        raise NotFoundError("track not found")
    return track


def cohort_track_or_404(db: Session, *, tenant_id: UUID, cohort_id: UUID, track_id: UUID) -> CohortTrack:
    cohort_track = db.scalars(
        select(CohortTrack)
        .join(Track, (Track.id == CohortTrack.track_id) & (Track.tenant_id == CohortTrack.tenant_id))
        .where(CohortTrack.tenant_id == tenant_id)
        .where(CohortTrack.cohort_id == cohort_id)
        .where(CohortTrack.track_id == track_id)
        .where(CohortTrack.status == "active")
        .where(Track.status == "active")
    ).first()
    if cohort_track is None:
        raise NotFoundError("track not found for cohort")
    return cohort_track


def ensure_track_offerings(db: Session, *, tenant_id: UUID, cohort_id: UUID, track_id: UUID) -> None:
    cohort_track_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track_id)
    course_ids = db.scalars(
        select(TrackCourse.course_id).where(TrackCourse.tenant_id == tenant_id).where(TrackCourse.track_id == track_id)
    ).all()
    for course_id in course_ids:
        offering = db.scalars(
            select(CourseOffering)
            .where(CourseOffering.tenant_id == tenant_id)
            .where(CourseOffering.cohort_id == cohort_id)
            .where(CourseOffering.course_id == course_id)
        ).first()
        if offering is None:
            db.add(CourseOffering(tenant_id=tenant_id, cohort_id=cohort_id, course_id=course_id, status="active"))
        else:
            offering.status = "active"
    db.flush()


def assign_enrollment_track(
    db: Session,
    *,
    tenant_id: UUID,
    cohort_id: UUID,
    person_id: UUID,
    track_id: UUID,
) -> Enrollment:
    cohort_track_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track_id)
    ensure_track_offerings(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track_id)
    enrollment = db.scalars(
        select(Enrollment)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.person_id == person_id)
    ).first()
    if enrollment is None:
        raise NotFoundError("enrollment not found")
    enrollment.track_id = track_id
    db.flush()
    return enrollment


def default_track_for_cohort(db: Session, *, tenant_id: UUID, cohort_id: UUID) -> Track | None:
    row = (
        db.execute(
            select(Track)
            .join(CohortTrack, (CohortTrack.track_id == Track.id) & (CohortTrack.tenant_id == Track.tenant_id))
            .where(CohortTrack.tenant_id == tenant_id)
            .where(CohortTrack.cohort_id == cohort_id)
            .where(CohortTrack.status == "active")
            .where(Track.status == "active")
            .order_by(Track.created_at, Track.name)
        )
        .scalars()
        .first()
    )
    return row


def ensure_default_track_for_cohort(db: Session, *, tenant_id: UUID, cohort_id: UUID) -> Track:
    existing = default_track_for_cohort(db, tenant_id=tenant_id, cohort_id=cohort_id)
    if existing is not None:
        return existing
    cohort = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.id == cohort_id)).first()
    if cohort is None:
        raise NotFoundError("cohort not found for tenant")
    name = f"{cohort.name} Track"
    track = Track(
        tenant_id=tenant_id,
        slug=_unique_track_slug(db, tenant_id=tenant_id, name=name),
        name=name,
    )
    db.add(track)
    db.flush()
    db.add(CohortTrack(tenant_id=tenant_id, cohort_id=cohort_id, track_id=track.id, status="active"))
    db.flush()
    return track
