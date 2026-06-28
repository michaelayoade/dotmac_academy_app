# app/services/agenda.py
"""Learner calendar / agenda service."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.pacing import OfferingActivity
from app.services.entitlements import accessible_course_ids


def upcoming_for_person(
    db: Session, *, tenant_id: UUID, person_id: UUID, limit: int = 50
) -> list[dict]:
    """Merged, chronologically-sorted future agenda items for a person.

    Returns offering window open/close events and activity due_at deadlines
    across the person's accessible courses. Past items are excluded.
    Each item: {when, kind, title, course, link}.
    """
    now = datetime.now(UTC)
    course_ids = accessible_course_ids(db, tenant_id=tenant_id, person_id=person_id)
    if not course_ids:
        return []

    courses_by_id: dict[UUID, Course] = {
        c.id: c
        for c in db.scalars(
            select(Course)
            .where(Course.tenant_id == tenant_id)
            .where(Course.id.in_(course_ids))
        ).all()
    }

    items: list[dict] = []

    for off in db.scalars(
        select(CourseOffering)
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(CourseOffering.course_id.in_(course_ids))
    ).all():
        course = courses_by_id.get(off.course_id)
        if course is None:
            continue
        if off.starts_at is not None and off.starts_at > now:
            items.append({
                "when": off.starts_at,
                "kind": "opens",
                "title": f"{course.title} opens",
                "course": course.title,
                "link": f"/courses/{course.slug}",
            })
        if off.ends_at is not None and off.ends_at > now:
            items.append({
                "when": off.ends_at,
                "kind": "closes",
                "title": f"{course.title} closes",
                "course": course.title,
                "link": f"/courses/{course.slug}",
            })

    rows = db.execute(
        select(OfferingActivity, Activity, Course)
        .join(
            Activity,
            (Activity.id == OfferingActivity.activity_id)
            & (Activity.tenant_id == OfferingActivity.tenant_id),
        )
        .join(
            CourseOffering,
            (CourseOffering.id == OfferingActivity.offering_id)
            & (CourseOffering.tenant_id == OfferingActivity.tenant_id),
        )
        .join(
            Course,
            (Course.id == CourseOffering.course_id)
            & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .where(OfferingActivity.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(CourseOffering.course_id.in_(course_ids))
        .where(OfferingActivity.due_at.isnot(None))
        .where(OfferingActivity.due_at > now)
    ).all()

    for pa, act, course in rows:
        assert pa.due_at is not None
        items.append({
            "when": pa.due_at,
            "kind": "due",
            "title": act.title,
            "course": course.title,
            "link": f"/activities/{act.id}",
        })

    items.sort(key=lambda x: x["when"])
    return items[:limit]
