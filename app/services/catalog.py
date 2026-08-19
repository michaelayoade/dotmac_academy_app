# app/services/catalog.py
"""Course catalog service — discovery + structure for learners and staff."""

from __future__ import annotations

from collections import defaultdict
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.course import Chapter, Course
from app.services.course_access_requests import status_for_course
from app.services.assessment import best_scores_for
from app.services.entitlements import unmet_prerequisites, visible_course_ids


def my_courses(db: Session, *, tenant_id: UUID, person_id: UUID) -> list[Course]:
    """Courses the person is entitled to see, ordered by title."""
    ids = visible_course_ids(db, tenant_id=tenant_id, person_id=person_id)
    if not ids:
        return []
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tenant_id)
            .where(Course.id.in_(ids))
            .order_by(Course.title)
        ).all()
    )


def public_catalog(db: Session, *, tenant_id: UUID) -> list[dict]:
    """The anonymous public-catalog projection: listed published courses.

    ``Course.listed`` is the single canonical selector — routes must not add
    their own slug/discipline filters on top. Returns one dict per course with
    the chapter count so the template renders without further queries.
    """
    rows = db.execute(
        select(Course, func.count(Chapter.id))
        .outerjoin(
            Chapter,
            (Chapter.tenant_id == Course.tenant_id) & (Chapter.course_id == Course.id),
        )
        .where(Course.tenant_id == tenant_id)
        .where(Course.status == "published")
        .where(Course.listed.is_(True))
        .group_by(Course.id)
        .order_by(Course.title)
    ).all()
    return [
        {"course": course, "chapter_count": int(chapters)} for course, chapters in rows
    ]


def all_courses(db: Session, *, tenant_id: UUID) -> list[Course]:
    """Every course belonging to the tenant, ordered by title."""
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tenant_id)
            .order_by(Course.title)
        ).all()
    )


def course_completion(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> int:
    """Return passed activities / total activities as an integer 0-100.

    Returns 0 for courses with no activities.
    """
    total = (
        db.scalar(
            select(func.count())
            .select_from(Activity)
            .where(Activity.tenant_id == tenant_id)
            .where(Activity.course_id == course_id)
        )
        or 0
    )
    if total == 0:
        return 0
    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    passed = sum(1 for s in best.values() if s.passed)
    return round(100 * passed / total)


def course_structure(
    db: Session, *, tenant_id: UUID, person_id: UUID, course: Course
) -> dict:
    """Build a Part-grouped view of the course for the landing page.

    Returns::

        {
            "parts": [
                {
                    "part": str,           # Chapter.part value (may be "")
                    "chapters": [
                        {
                            "chapter": Chapter,
                            "activities": [
                                {"activity": Activity, "passed": bool, "pct": int}
                            ],
                        }
                    ],
                }
            ],
            "course_activities": [               # course-level (no chapter): mid/final
                {"activity": Activity, "passed": bool, "pct": int}
            ],
            "continue_target": Chapter | None,  # first chapter with an unpassed activity
            "locked": bool,                     # True when unmet prerequisites exist
        }
    """
    locked = bool(
        unmet_prerequisites(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)
    )
    request_status = status_for_course(
        db, tenant_id=tenant_id, person_id=person_id, course_id=course.id
    )
    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)

    chapters = list(
        db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant_id)
            .where(Chapter.course_id == course.id)
            .order_by(Chapter.order_index, Chapter.number)
        ).all()
    )

    # Fetch all activities for the course in one query, keyed by chapter_number.
    all_acts = db.scalars(
        select(Activity)
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id == course.id)
    ).all()
    acts_by_chapter: dict[int | None, list[Activity]] = defaultdict(list)
    for act in all_acts:
        acts_by_chapter[act.chapter_number].append(act)

    passed_act_ids = {aid for aid, s in best.items() if s.passed}

    # Group chapters by part, preserving encounter order of parts.
    seen_parts: list[str] = []
    parts_map: dict[str, list[dict]] = {}
    continue_target: Chapter | None = None

    for ch in chapters:
        ch_acts = acts_by_chapter.get(ch.number, [])
        ch_act_list = [
            {
                "activity": act,
                "passed": bool(best.get(act.id) and best[act.id].passed),
                "pct": round(100 * best[act.id].fraction) if best.get(act.id) else 0,
            }
            for act in ch_acts
        ]

        # continue_target: first chapter where first activity is missing or unpassed
        # (mirrors the learn-home logic so navigation is consistent).
        if continue_target is None:
            first_act = ch_acts[0] if ch_acts else None
            if first_act is None or first_act.id not in passed_act_ids:
                continue_target = ch

        part_key = ch.part or ""
        if part_key not in seen_parts:
            seen_parts.append(part_key)
            parts_map[part_key] = []
        parts_map[part_key].append({"chapter": ch, "activities": ch_act_list})

    parts = [{"part": pk, "chapters": parts_map[pk]} for pk in seen_parts]

    # Course-level activities (mid/final assessments) carry no chapter_number, so
    # they belong to no chapter card and were previously rendered nowhere at all —
    # invisible to learners while still counting towards completion, which made
    # every affected course impossible to finish. They surface as their own
    # section after the chapters.
    course_activities = [
        {
            "activity": act,
            "passed": bool(best.get(act.id) and best[act.id].passed),
            "pct": round(100 * best[act.id].fraction) if best.get(act.id) else 0,
        }
        for act in sorted(acts_by_chapter.get(None, []), key=lambda a: a.title)
    ]

    return {
        "parts": parts,
        "course_activities": course_activities,
        "continue_target": continue_target,
        "locked": locked,
        "request_status": request_status,
    }
