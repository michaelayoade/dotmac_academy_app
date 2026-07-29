"""Learner dashboard projections (roadmap P1a).

This service OWNS the learner-facing dashboard, resume, and progress
projections: each course card carries ONE derived state and ONE action, the
resume target is computed server-side from the last meaningful touch (so it
follows the learner across devices), and the progress overview aggregates
grades, attempts, deadlines and certificate eligibility per course. Routes
render these dicts; they do not re-derive state.

States (mutually exclusive, in precedence order):
    locked > upcoming > completed > expired > in_progress
``in_progress`` covers not-yet-started courses too — the card's action
(Start vs Resume) is what distinguishes them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Activity, Score, Submission
from app.models.attempt import ActivityAttempt
from app.models.certificate import Certificate
from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Chapter, Course
from app.models.offering import CourseOffering
from app.models.pacing import OfferingActivity
from app.models.reading import ChapterRead
from app.services import scheduling
from app.services.assessment import attempts_used, best_scores_for, reveal_feedback
from app.services.entitlements import course_access_states, visible_course_ids
from app.services.gradebook import course_grade

_STATES = ("in_progress", "upcoming", "completed", "expired", "locked")


def _entitled_courses(db: Session, tenant_id: UUID, person_id: UUID) -> list[tuple[Course, CourseOffering]]:
    """(course, offering) pairs the person can see, one row per course.

    Visibility is OWNED by entitlements.visible_course_ids — this query only
    attaches the binding offering window to each visible course. When several
    active offerings cover the same course, the one with the earliest end
    (soonest deadline) wins.
    """
    allowed = visible_course_ids(db, tenant_id=tenant_id, person_id=person_id)
    if not allowed:
        return []
    rows = db.execute(
        select(Course, CourseOffering)
        .join(
            CourseOffering,
            (CourseOffering.course_id == Course.id)
            & (CourseOffering.tenant_id == Course.tenant_id),
        )
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .where(Course.tenant_id == tenant_id)
        .where(Course.id.in_(allowed))
        .where(CourseOffering.status == "active")
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .order_by(Course.title)
    ).all()
    chosen: dict[UUID, tuple[Course, CourseOffering]] = {}
    for course, offering in rows:
        held = chosen.get(course.id)
        if held is None:
            chosen[course.id] = (course, offering)
            continue
        held_end = held[1].ends_at
        this_end = offering.ends_at
        if this_end is not None and (held_end is None or this_end < held_end):
            chosen[course.id] = (course, offering)
    return sorted(chosen.values(), key=lambda pair: pair[0].title)


def _chapters(db: Session, tenant_id: UUID, course_id: UUID) -> list[Chapter]:
    return list(
        db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant_id)
            .where(Chapter.course_id == course_id)
            .order_by(Chapter.number)
        ).all()
    )


def _activities(db: Session, tenant_id: UUID, course_id: UUID) -> list[Activity]:
    return list(
        db.scalars(
            select(Activity)
            .where(Activity.tenant_id == tenant_id)
            .where(Activity.course_id == course_id)
            .order_by(Activity.chapter_number, Activity.type)
        ).all()
    )


def _last_touch(db: Session, tenant_id: UUID, person_id: UUID, course_id: UUID) -> tuple[datetime, int] | None:
    """(when, chapter_number) of the person's most recent meaningful touch.

    Meaningful = chapter read, submission made, or attempt opened. Stored
    server-side, so resume follows the learner across devices.
    """
    candidates: list[tuple[datetime, int]] = []

    read_row = db.execute(
        select(ChapterRead.created_at, Chapter.number)
        .join(Chapter, (Chapter.id == ChapterRead.chapter_id))
        .where(ChapterRead.tenant_id == tenant_id)
        .where(ChapterRead.person_id == person_id)
        .where(Chapter.course_id == course_id)
        .order_by(ChapterRead.created_at.desc())
    ).first()
    if read_row is not None:
        candidates.append((read_row[0], read_row[1]))

    sub_row = db.execute(
        select(Submission.created_at, Activity.chapter_number)
        .join(Activity, (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id))
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .where(Activity.course_id == course_id)
        .order_by(Submission.created_at.desc())
    ).first()
    if sub_row is not None:
        candidates.append((sub_row[0], sub_row[1]))

    att_row = db.execute(
        select(ActivityAttempt.started_at, Activity.chapter_number)
        .join(
            Activity,
            (Activity.id == ActivityAttempt.activity_id)
            & (Activity.tenant_id == ActivityAttempt.tenant_id),
        )
        .where(ActivityAttempt.tenant_id == tenant_id)
        .where(ActivityAttempt.person_id == person_id)
        .where(Activity.course_id == course_id)
        .order_by(ActivityAttempt.started_at.desc())
    ).first()
    if att_row is not None:
        candidates.append((att_row[0], att_row[1]))

    if not candidates:
        return None
    return max(candidates, key=lambda c: c[0])


def resume_chapter(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> Chapter | None:
    """The chapter to resume at: the first incomplete chapter at or after the
    last touched one (wrapping to the start), or None when nothing remains."""
    chapters = _chapters(db, tenant_id, course_id)
    if not chapters:
        return None
    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    passed_acts = {aid for aid, s in best.items() if s.passed}
    acts_by_chapter: dict[int, list[Activity]] = {}
    for a in _activities(db, tenant_id, course_id):
        if a.chapter_number is None:
            continue
        acts_by_chapter.setdefault(a.chapter_number, []).append(a)
    read_numbers = {
        n
        for (n,) in db.execute(
            select(Chapter.number)
            .join(ChapterRead, ChapterRead.chapter_id == Chapter.id)
            .where(ChapterRead.tenant_id == tenant_id)
            .where(ChapterRead.person_id == person_id)
            .where(Chapter.course_id == course_id)
        ).all()
    }

    def incomplete(ch: Chapter) -> bool:
        acts = acts_by_chapter.get(ch.number, [])
        acts_done = all(a.id in passed_acts for a in acts) if acts else True
        return not (acts_done and ch.number in read_numbers)

    touch = _last_touch(db, tenant_id, person_id, course_id)
    start_number = touch[1] if touch is not None else chapters[0].number
    ordered = [c for c in chapters if c.number >= start_number] + [
        c for c in chapters if c.number < start_number
    ]
    for ch in ordered:
        if incomplete(ch):
            return ch
    return None


def continue_target(db: Session, *, tenant_id: UUID, person_id: UUID) -> dict | None:
    """Cross-course resume: the most recently touched course's resume chapter."""
    latest: tuple[datetime, Course] | None = None
    for course, _off in _entitled_courses(db, tenant_id, person_id):
        touch = _last_touch(db, tenant_id, person_id, course.id)
        if touch is not None and (latest is None or touch[0] > latest[0]):
            latest = (touch[0], course)
    if latest is None:
        return None
    chapter = resume_chapter(db, tenant_id=tenant_id, person_id=person_id, course_id=latest[1].id)
    if chapter is None:
        return None
    return {"course": latest[1], "chapter": chapter}


def _next_deadline(
    db: Session, tenant_id: UUID, offering: CourseOffering, now: datetime
) -> datetime | None:
    """Earliest future deadline: pacing due dates, else the offering close."""
    deadlines = [
        due
        for (due,) in db.execute(
            select(OfferingActivity.due_at)
            .where(OfferingActivity.tenant_id == tenant_id)
            .where(OfferingActivity.offering_id == offering.id)
            .where(OfferingActivity.due_at.is_not(None))
        ).all()
        if due is not None and due > now
    ]
    if offering.ends_at is not None and offering.ends_at > now:
        deadlines.append(offering.ends_at)
    return min(deadlines) if deadlines else None


def course_cards(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> dict:
    """The My Courses projection: cards with one state and one action each.

    Returns {"cards": [...], "counts": {state: n}, "filters": [...]}.
    """
    now = now or datetime.now(UTC)
    pairs = _entitled_courses(db, tenant_id, person_id)
    access = course_access_states(db, tenant_id=tenant_id, person_id=person_id)
    completions = {
        c.course_id: c
        for c in db.scalars(
            select(CourseCompletion)
            .where(CourseCompletion.tenant_id == tenant_id)
            .where(CourseCompletion.person_id == person_id)
        ).all()
    }
    certificates = {
        c.course_id: c
        for c in db.scalars(
            select(Certificate)
            .where(Certificate.tenant_id == tenant_id)
            .where(Certificate.person_id == person_id)
        ).all()
    }
    sessions = scheduling.list_for_person(db, tenant_id=tenant_id, person_id=person_id, now=now)
    next_session_by_cohort: dict[UUID, object] = {}
    for session, _cohort_name in sessions["upcoming"]:
        next_session_by_cohort.setdefault(session.cohort_id, session)

    cards: list[dict] = []
    counts = dict.fromkeys(_STATES, 0)
    for course, offering in pairs:
        activities = _activities(db, tenant_id, course.id)
        best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)
        total = len(activities)
        passed = sum(1 for a in activities if a.id in best and best[a.id].passed)
        pct = round(100 * passed / total) if total else 0
        grade = course_grade(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)
        final_threshold = max((a.pass_threshold for a in activities), default=0.0)

        completion = completions.get(course.id)
        state_info = access.get(course.id)
        touch = _last_touch(db, tenant_id, person_id, course.id)

        if state_info is not None and state_info.locked:
            state = "locked"
        elif offering.starts_at is not None and offering.starts_at > now:
            state = "upcoming"
        elif completion is not None and completion.status == "completed":
            state = "completed"
        elif offering.ends_at is not None and offering.ends_at < now:
            state = "expired"
        else:
            state = "in_progress"
        counts[state] += 1

        next_activity = next((a for a in activities if a.id not in best or not best[a.id].passed), None)

        last_read_row = db.execute(
            select(Chapter.number, Chapter.title)
            .join(ChapterRead, ChapterRead.chapter_id == Chapter.id)
            .where(ChapterRead.tenant_id == tenant_id)
            .where(ChapterRead.person_id == person_id)
            .where(Chapter.course_id == course.id)
            .order_by(ChapterRead.created_at.desc())
        ).first()

        certificate = certificates.get(course.id)
        if certificate is not None:
            cert_status = "issued"
        elif state == "completed":
            cert_status = "eligible"
        else:
            cert_status = None

        action = None
        if state == "in_progress":
            if touch is None:
                action = {"label": "Start", "href": f"/courses/{course.slug}/chapters/1"}
            else:
                target = resume_chapter(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)
                number = target.number if target is not None else 1
                action = {"label": "Resume", "href": f"/courses/{course.slug}/chapters/{number}"}
        elif state == "completed":
            action = {"label": "Review feedback", "href": f"/progress#course-{course.id}"}

        cards.append(
            {
                "course": course,
                "state": state,
                "pct": pct,
                "passed": passed,
                "total": total,
                "grade_pct": grade["pct"],
                "final_threshold_pct": int(round(final_threshold * 100)),
                "next_activity": next_activity,
                "next_deadline": _next_deadline(db, tenant_id, offering, now),
                "starts_at": offering.starts_at,
                "last_read": (
                    {"number": last_read_row[0], "title": last_read_row[1]}
                    if last_read_row is not None
                    else None
                ),
                "next_session": next_session_by_cohort.get(offering.cohort_id),
                "certificate_status": cert_status,
                "locked_reason": state_info.locked_reason if state_info is not None and state_info.locked else None,
                "action": action,
            }
        )
    return {"cards": cards, "counts": counts, "filters": list(_STATES)}


def _trend(points: list[int]) -> str:
    if len(points) < 3:
        return "flat"
    half = len(points) // 2
    earlier = sum(points[:half]) / half
    later = sum(points[half:]) / (len(points) - half)
    if later - earlier > 3:
        return "up"
    if earlier - later > 3:
        return "down"
    return "flat"


def progress_overview(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> list[dict]:
    """The rich per-course progress projection for /progress."""
    now = now or datetime.now(UTC)
    out: list[dict] = []
    for course, offering in _entitled_courses(db, tenant_id, person_id):
        activities = _activities(db, tenant_id, course.id)
        best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)
        grade = course_grade(db, tenant_id=tenant_id, person_id=person_id, course_id=course.id)
        due_by_activity = {
            activity_id: due
            for activity_id, due in db.execute(
                select(OfferingActivity.activity_id, OfferingActivity.due_at)
                .where(OfferingActivity.tenant_id == tenant_id)
                .where(OfferingActivity.offering_id == offering.id)
            ).all()
        }

        rows: list[dict] = []
        upcoming: list[dict] = []
        overdue: list[dict] = []
        for a in activities:
            score = best.get(a.id)
            used = attempts_used(db, tenant_id=tenant_id, person_id=person_id, activity_id=a.id)
            remaining = None if a.max_attempts is None else max(a.max_attempts - used, 0)
            due = due_by_activity.get(a.id) or offering.ends_at
            is_passed = score is not None and score.passed
            is_overdue = due is not None and due < now and not is_passed
            row = {
                "activity": a,
                "chapter_number": a.chapter_number,
                "score": score,
                "pct": round(100 * score.fraction) if score is not None else None,
                "passed": is_passed,
                "threshold_pct": int(round(a.pass_threshold * 100)),
                "attempts_used": used,
                "max_attempts": a.max_attempts,
                "attempts_left": remaining,
                "feedback_available": (
                    score is not None
                    and reveal_feedback(a, passed=score.passed, attempts_used=used)
                ),
                "due_at": due,
                "overdue": is_overdue,
            }
            rows.append(row)
            if is_overdue:
                overdue.append(row)
            elif due is not None and due > now and not is_passed:
                upcoming.append(row)

        score_points = [
            round(100 * fraction)
            for (fraction,) in db.execute(
                select(Score.fraction)
                .join(
                    Submission,
                    (Submission.id == Score.submission_id) & (Submission.tenant_id == Score.tenant_id),
                )
                .join(
                    Activity,
                    (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id),
                )
                .where(Score.tenant_id == tenant_id)
                .where(Submission.person_id == person_id)
                .where(Activity.course_id == course.id)
                .order_by(Score.created_at.asc())
            ).all()
        ][-8:]

        completion = db.scalars(
            select(CourseCompletion)
            .where(CourseCompletion.tenant_id == tenant_id)
            .where(CourseCompletion.person_id == person_id)
            .where(CourseCompletion.course_id == course.id)
        ).first()
        certificate = db.scalars(
            select(Certificate)
            .where(Certificate.tenant_id == tenant_id)
            .where(Certificate.person_id == person_id)
            .where(Certificate.course_id == course.id)
        ).first()
        completed = completion is not None and completion.status == "completed"

        out.append(
            {
                "course": course,
                "grade_pct": grade["pct"],
                "completion_pct": round(100 * completion.pct) if completion is not None else 0,
                "final_threshold_pct": int(
                    round(max((a.pass_threshold for a in activities), default=0.0) * 100)
                ),
                "rows": rows,
                "upcoming": sorted(upcoming, key=lambda r: r["due_at"]),
                "overdue": overdue,
                "trend_points": score_points,
                "trend": _trend(score_points),
                "certificate": {
                    "status": "issued" if certificate is not None else ("eligible" if completed else None),
                    "serial": certificate.serial if certificate is not None else None,
                    "href": f"/certificates/{course.id}" if completed else None,
                },
            }
        )
    return out
