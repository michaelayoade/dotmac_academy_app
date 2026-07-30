"""Unified learner To-Do timeline — the single owner of the "what's next" projection.

``timeline_for_person`` derives every section from canonical records: pacing
deadlines (OfferingActivity.due_at) against not-yet-passed activities, the
learner's class sessions, recent Scores, and offering windows. Routes and the
iCal feed render this projection; they add no derivation of their own
(roadmap P1 item 7; ADR-adjacent to the SOT adapter rules).

"Unread feedback" has no read-receipt in the schema; the closest canonical
signal is recently graded work whose per-question feedback is revealable
(``assessment.reveal_feedback``). That is what the ``feedback`` section holds.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.pacing import OfferingActivity
from app.services.assessment import attempts_used, reveal_feedback
from app.services.localtime import academy_zone
from app.services.scheduling import join_is_open, list_for_person

GRADED_LOOKBACK_DAYS = 14
WINDOW_HORIZON_DAYS = 30


def _passed_activity_ids(db: Session, *, tenant_id: UUID, person_id: UUID) -> set[UUID]:
    rows = db.scalars(
        select(Submission.activity_id)
        .join(Score, (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id))
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .where(Score.passed.is_(True))
        .distinct()
    ).all()
    return set(rows)


def _deadline_rows(db: Session, *, tenant_id: UUID, person_id: UUID) -> list[dict]:
    """Every dated, not-yet-passed activity deadline across active offerings."""
    rows = db.execute(
        select(OfferingActivity.due_at, Activity, Course.title, Course.slug)
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
            (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .where(OfferingActivity.tenant_id == tenant_id)
        .where(OfferingActivity.due_at.is_not(None))
        .where(CourseOffering.status == "active")
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .where(Enrollment.role_in_cohort == "student")
        .order_by(OfferingActivity.due_at)
    ).all()
    passed = _passed_activity_ids(db, tenant_id=tenant_id, person_id=person_id)
    out = []
    for due_at, activity, course_title, course_slug in rows:
        if activity.id in passed:
            continue
        out.append({
            "due_at": due_at,
            "activity": activity,
            "course_title": course_title,
            "course_slug": course_slug,
        })
    return out


def _local_day_end(now: datetime) -> datetime:
    """End of "today" in the academy's wall-clock zone, as aware UTC."""
    local = now.astimezone(academy_zone())
    end_local = local.replace(hour=23, minute=59, second=59, microsecond=0)
    return end_local.astimezone(UTC)


def _graded_rows(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime) -> list[dict]:
    since = now - timedelta(days=GRADED_LOOKBACK_DAYS)
    rows = db.execute(
        select(Score, Activity, Course.title)
        .join(Submission, (Submission.id == Score.submission_id) & (Submission.tenant_id == Score.tenant_id))
        .join(Activity, (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id))
        .join(Course, (Course.id == Activity.course_id) & (Course.tenant_id == Activity.tenant_id))
        .where(Score.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .where(Score.created_at >= since)
        .order_by(Score.created_at.desc())
        .limit(10)
    ).all()
    out = []
    for score, activity, course_title in rows:
        used = attempts_used(db, tenant_id=tenant_id, person_id=person_id, activity_id=activity.id)
        out.append(
            {
                "score": score,
                "activity": activity,
                "course_title": course_title,
                "feedback_available": reveal_feedback(activity, passed=score.passed, attempts_used=used),
            }
        )
    return out


def _course_windows(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime) -> list[dict]:
    horizon = now + timedelta(days=WINDOW_HORIZON_DAYS)
    rows = db.execute(
        select(CourseOffering, Course.title)
        .join(Course, (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id))
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
    ).all()
    out: list[dict] = []
    for off, title in rows:
        if off.starts_at is not None and now < off.starts_at <= horizon:
            out.append({"kind": "opens", "at": off.starts_at, "course_title": title})
        if off.ends_at is not None and now < off.ends_at <= horizon:
            out.append({"kind": "closes", "at": off.ends_at, "course_title": title})
    out.sort(key=lambda w: w["at"])
    return out


def timeline_for_person(
    db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None
) -> dict:
    """The unified To-Do projection: sectioned deadlines, sessions, grades, windows."""
    now = now or datetime.now(UTC)
    day_end = _local_day_end(now)
    week_end = now + timedelta(days=7)
    month_end = now + timedelta(days=30)

    overdue: list[dict] = []
    due_today: list[dict] = []
    next_7: list[dict] = []
    next_30: list[dict] = []
    for row in _deadline_rows(db, tenant_id=tenant_id, person_id=person_id):
        due = row["due_at"]
        if due < now:
            overdue.append(row)
        elif due <= day_end:
            due_today.append(row)
        elif due <= week_end:
            next_7.append(row)
        elif due <= month_end:
            next_30.append(row)

    sessions = list_for_person(db, tenant_id=tenant_id, person_id=person_id, now=now)["upcoming"]
    joinable = {s.id for s, _name in sessions if join_is_open(s, now=now)}
    graded = _graded_rows(db, tenant_id=tenant_id, person_id=person_id, now=now)

    return {
        "overdue": overdue,
        "due_today": due_today,
        "next_7": next_7,
        "next_30": next_30,
        "sessions": sessions,
        "joinable": joinable,
        "graded": graded,
        "feedback": [g for g in graded if g["feedback_available"]],
        "course_windows": _course_windows(db, tenant_id=tenant_id, person_id=person_id, now=now),
    }
