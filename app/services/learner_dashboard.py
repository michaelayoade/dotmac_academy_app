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
from app.services import attempt_policy, scheduling
from app.services.assessment import (
    attempts_used_by_person,
    best_scores_for,
    best_scores_for_person,
    reveal_feedback,
)
from app.services.course_access_requests import status_by_courses
from app.services.entitlements import course_access_states, visible_course_ids
from app.services.gradebook import grade_from

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
        select(Course, CourseOffering, Enrollment.access_ends_at)
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
    for course, offering, access_ends_at in rows:
        if access_ends_at is not None and (offering.ends_at is None or access_ends_at > offering.ends_at):
            offering.effective_ends_at = access_ends_at
        else:
            offering.effective_ends_at = offering.ends_at
        held = chosen.get(course.id)
        if held is None:
            chosen[course.id] = (course, offering)
            continue
        held_end = getattr(held[1], "effective_ends_at", held[1].ends_at)
        this_end = getattr(offering, "effective_ends_at", offering.ends_at)
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


# ---------------------------------------------------------------------------
# Batched primitives — each computes across ALL of the person's courses in a
# bounded number of queries, so the dashboard/progress render cost does not
# scale with the number of enrolled courses (roadmap review item 5).
# ---------------------------------------------------------------------------


def _by_course(rows, key_index: int = -1) -> dict:
    out: dict = {}
    for row in rows:
        out.setdefault(row[key_index], []).append(row)
    return out


def _activities_by_course(db, tenant_id, course_ids) -> dict[UUID, list[Activity]]:
    if not course_ids:
        return {}
    acts = db.scalars(
        select(Activity)
        .where(Activity.tenant_id == tenant_id)
        .where(Activity.course_id.in_(course_ids))
        .order_by(Activity.chapter_number, Activity.type)
    ).all()
    out: dict[UUID, list[Activity]] = {}
    for a in acts:
        out.setdefault(a.course_id, []).append(a)
    return out


def _chapters_by_course(db, tenant_id, course_ids) -> dict[UUID, list[Chapter]]:
    if not course_ids:
        return {}
    chs = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant_id)
        .where(Chapter.course_id.in_(course_ids))
        .order_by(Chapter.number)
    ).all()
    out: dict[UUID, list[Chapter]] = {}
    for c in chs:
        out.setdefault(c.course_id, []).append(c)
    return out


def _touch_bundle(db, tenant_id, person_id, course_ids) -> dict:
    """Per-course last-touch + last-read + read chapter numbers, in 3 queries.

    Returns {"last_touch": {course_id: (when, chapter_number)},
             "last_read": {course_id: (number, title)},
             "read_numbers": {course_id: set[int]}}.
    'when' is the max across chapter reads, submissions, and opened attempts.
    """
    last_touch: dict[UUID, tuple[datetime, int]] = {}
    last_read: dict[UUID, tuple[int, str]] = {}
    read_numbers: dict[UUID, set[int]] = {}
    if not course_ids:
        return {"last_touch": {}, "last_read": {}, "read_numbers": {}}

    def _offer(course_id, when, chapter_number):
        if chapter_number is None:
            return
        held = last_touch.get(course_id)
        if held is None or when > held[0]:
            last_touch[course_id] = (when, chapter_number)

    reads = db.execute(
        select(Chapter.course_id, ChapterRead.created_at, Chapter.number, Chapter.title)
        .join(Chapter, Chapter.id == ChapterRead.chapter_id)
        .where(ChapterRead.tenant_id == tenant_id)
        .where(ChapterRead.person_id == person_id)
        .where(Chapter.course_id.in_(course_ids))
        .order_by(ChapterRead.created_at.desc())
    ).all()
    for course_id, when, number, title in reads:
        read_numbers.setdefault(course_id, set()).add(number)
        if course_id not in last_read:  # rows are newest-first
            last_read[course_id] = (number, title)
        _offer(course_id, when, number)

    subs = db.execute(
        select(Activity.course_id, Submission.created_at, Activity.chapter_number)
        .join(Activity, (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id))
        .where(Submission.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .where(Activity.course_id.in_(course_ids))
    ).all()
    for course_id, when, chapter_number in subs:
        _offer(course_id, when, chapter_number)

    atts = db.execute(
        select(Activity.course_id, ActivityAttempt.started_at, Activity.chapter_number)
        .join(
            Activity,
            (Activity.id == ActivityAttempt.activity_id)
            & (Activity.tenant_id == ActivityAttempt.tenant_id),
        )
        .where(ActivityAttempt.tenant_id == tenant_id)
        .where(ActivityAttempt.person_id == person_id)
        .where(Activity.course_id.in_(course_ids))
    ).all()
    for course_id, when, chapter_number in atts:
        _offer(course_id, when, chapter_number)

    return {"last_touch": last_touch, "last_read": last_read, "read_numbers": read_numbers}


def _due_by_offering(db, tenant_id, offering_ids) -> dict[UUID, list]:
    """All (activity_id, due_at) pacing rows grouped by offering, in ONE query."""
    if not offering_ids:
        return {}
    rows = db.execute(
        select(OfferingActivity.offering_id, OfferingActivity.activity_id, OfferingActivity.due_at)
        .where(OfferingActivity.tenant_id == tenant_id)
        .where(OfferingActivity.offering_id.in_(offering_ids))
    ).all()
    out: dict[UUID, list] = {}
    for offering_id, activity_id, due in rows:
        out.setdefault(offering_id, []).append((activity_id, due))
    return out


def _resume_from(
    chapters: list[Chapter],
    activities: list[Activity],
    best: dict,
    read_numbers: set[int],
    last_touch: tuple[datetime, int] | None,
) -> Chapter | None:
    """Pure resume computation from already-fetched data (no queries)."""
    if not chapters:
        return None
    passed_acts = {aid for aid, s in best.items() if s.passed}
    acts_by_chapter: dict[int, list[Activity]] = {}
    for a in activities:
        if a.chapter_number is None:
            continue
        acts_by_chapter.setdefault(a.chapter_number, []).append(a)

    def incomplete(ch: Chapter) -> bool:
        acts = acts_by_chapter.get(ch.number, [])
        acts_done = all(a.id in passed_acts for a in acts) if acts else True
        return not (acts_done and ch.number in read_numbers)

    start_number = last_touch[1] if last_touch is not None else chapters[0].number
    ordered = [c for c in chapters if c.number >= start_number] + [
        c for c in chapters if c.number < start_number
    ]
    for ch in ordered:
        if incomplete(ch):
            return ch
    return None


def resume_chapter(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> Chapter | None:
    """The chapter to resume at: the first incomplete chapter at or after the
    last touched one (wrapping to the start), or None when nothing remains.

    Public single-course entry point (unchanged signature); the batched
    dashboard path uses :func:`_resume_from` with already-fetched data.
    """
    chapters = _chapters(db, tenant_id, course_id)
    if not chapters:
        return None
    best = best_scores_for(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    bundle = _touch_bundle(db, tenant_id, person_id, [course_id])
    return _resume_from(
        chapters,
        _activities(db, tenant_id, course_id),
        best,
        bundle["read_numbers"].get(course_id, set()),
        bundle["last_touch"].get(course_id),
    )


def continue_target(
    db: Session, *, tenant_id: UUID, person_id: UUID, _ctx: dict | None = None
) -> dict | None:
    """Cross-course resume: the most recently touched course's resume chapter.

    ``_ctx`` (from :func:`_dashboard_context`) lets ``learner_home`` share the
    already-computed touch/activity data so the ``/`` render fans out once, not
    twice (roadmap review item 5). Standalone callers pass nothing.
    """
    if _ctx is not None:
        pairs = _ctx["pairs"]
    else:
        pairs = _entitled_courses(db, tenant_id, person_id)
    if not pairs:
        return None
    courses_by_id = {c.id: c for c, _ in pairs}
    course_ids = [c.id for c, _ in pairs]
    bundle = _ctx["bundle"] if _ctx is not None else _touch_bundle(db, tenant_id, person_id, course_ids)
    last_touch = bundle["last_touch"]
    latest_course_id = None
    latest_when = None
    for cid in course_ids:
        t = last_touch.get(cid)
        if t is not None and (latest_when is None or t[0] > latest_when):
            latest_when, latest_course_id = t[0], cid
    if latest_course_id is None:
        return None
    if _ctx is not None:
        chapter = _resume_from(
            _ctx["chapters_by_course"].get(latest_course_id, []),
            _ctx["activities_by_course"].get(latest_course_id, []),
            _ctx["best"],
            bundle["read_numbers"].get(latest_course_id, set()),
            last_touch.get(latest_course_id),
        )
    else:
        chapter = resume_chapter(db, tenant_id=tenant_id, person_id=person_id, course_id=latest_course_id)
    if chapter is None:
        return None
    return {"course": courses_by_id[latest_course_id], "chapter": chapter}


def _next_deadline_from(due_rows: list, ends_at: datetime | None, now: datetime) -> datetime | None:
    """Earliest future deadline from already-fetched (activity_id, due) rows."""
    deadlines = [due for _aid, due in due_rows if due is not None and due > now]
    if ends_at is not None and ends_at > now:
        deadlines.append(ends_at)
    return min(deadlines) if deadlines else None


def _dashboard_context(db: Session, tenant_id: UUID, person_id: UUID, now: datetime | None) -> dict:
    """All batched inputs the dashboard + cross-course resume share, fetched
    once (bounded query count) so ``home()`` never recomputes per course."""
    now = now or datetime.now(UTC)
    pairs = _entitled_courses(db, tenant_id, person_id)
    course_ids = [c.id for c, _ in pairs]
    offering_ids = [o.id for _, o in pairs]
    sessions = scheduling.list_for_person(db, tenant_id=tenant_id, person_id=person_id, now=now)
    next_session_by_cohort: dict[UUID, object] = {}
    for session, _cohort_name in sessions["upcoming"]:
        next_session_by_cohort.setdefault(session.cohort_id, session)
    return {
        "now": now,
        "pairs": pairs,
        "course_ids": course_ids,
        "offering_ids": offering_ids,
        "access": course_access_states(db, tenant_id=tenant_id, person_id=person_id),
        "completions": {
            c.course_id: c
            for c in db.scalars(
                select(CourseCompletion)
                .where(CourseCompletion.tenant_id == tenant_id)
                .where(CourseCompletion.person_id == person_id)
            ).all()
        },
        "certificates": {
            c.course_id: c
            for c in db.scalars(
                select(Certificate)
                .where(Certificate.tenant_id == tenant_id)
                .where(Certificate.person_id == person_id)
            ).all()
        },
        "next_session_by_cohort": next_session_by_cohort,
        "activities_by_course": _activities_by_course(db, tenant_id, course_ids),
        "best": best_scores_for_person(db, tenant_id=tenant_id, person_id=person_id, course_ids=course_ids),
        "request_statuses": status_by_courses(
            db,
            tenant_id=tenant_id,
            person_id=person_id,
            course_ids=course_ids,
        ),
        "bundle": _touch_bundle(db, tenant_id, person_id, course_ids),
        "chapters_by_course": _chapters_by_course(db, tenant_id, course_ids),
        "due_by_offering": _due_by_offering(db, tenant_id, offering_ids),
    }


def learner_home(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> dict:
    """The `/` projection: cards + counts + filters + cross-course continue,
    all from a single shared batched context (one fan-out, not two)."""
    ctx = _dashboard_context(db, tenant_id, person_id, now)
    result = course_cards(db, tenant_id=tenant_id, person_id=person_id, _ctx=ctx)
    result["continue_to"] = continue_target(db, tenant_id=tenant_id, person_id=person_id, _ctx=ctx)
    return result


def course_cards(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None,
                 _ctx: dict | None = None) -> dict:
    """The My Courses projection: cards with one state and one action each.

    Returns {"cards": [...], "counts": {state: n}, "filters": [...]}.
    """
    ctx = _ctx if _ctx is not None else _dashboard_context(db, tenant_id, person_id, now)
    now = ctx["now"]
    pairs = ctx["pairs"]
    access = ctx["access"]
    completions = ctx["completions"]
    certificates = ctx["certificates"]
    next_session_by_cohort = ctx["next_session_by_cohort"]
    activities_by_course = ctx["activities_by_course"]
    best = ctx["best"]
    bundle = ctx["bundle"]
    request_statuses = ctx["request_statuses"]
    chapters_by_course = ctx["chapters_by_course"]
    due_by_offering = ctx["due_by_offering"]
    last_touch = bundle["last_touch"]
    last_read = bundle["last_read"]
    read_numbers = bundle["read_numbers"]

    cards: list[dict] = []
    counts = dict.fromkeys(_STATES, 0)
    for course, offering in pairs:
        activities = activities_by_course.get(course.id, [])
        total = len(activities)
        passed = sum(1 for a in activities if a.id in best and best[a.id].passed)
        pct = round(100 * passed / total) if total else 0
        grade = grade_from(activities, best)
        final_threshold = max((a.pass_threshold for a in activities), default=0.0)

        completion = completions.get(course.id)
        state_info = access.get(course.id)
        touch = last_touch.get(course.id)

        if state_info is not None and state_info.locked:
            state = "locked"
        elif offering.starts_at is not None and offering.starts_at > now:
            state = "upcoming"
        elif completion is not None and completion.status == "completed":
            state = "completed"
        else:
            effective_ends_at = getattr(offering, "effective_ends_at", offering.ends_at)
            state = "expired" if effective_ends_at is not None and effective_ends_at < now else "in_progress"
        counts[state] += 1

        next_activity = next((a for a in activities if a.id not in best or not best[a.id].passed), None)
        read_row = last_read.get(course.id)

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
                target = _resume_from(
                    chapters_by_course.get(course.id, []), activities, best,
                    read_numbers.get(course.id, set()), touch,
                )
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
                "next_deadline": _next_deadline_from(
                    due_by_offering.get(offering.id, []),
                    getattr(offering, "effective_ends_at", offering.ends_at),
                    now,
                ),
                "starts_at": offering.starts_at,
                "request_status": request_statuses.get(course.id),
                "last_read": (
                    {"number": read_row[0], "title": read_row[1]}
                    if read_row is not None
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
    pairs = _entitled_courses(db, tenant_id, person_id)
    course_ids = [c.id for c, _ in pairs]
    offering_ids = [o.id for _, o in pairs]

    # Batched fan-out (roadmap review item 5).
    activities_by_course = _activities_by_course(db, tenant_id, course_ids)
    best = best_scores_for_person(db, tenant_id=tenant_id, person_id=person_id, course_ids=course_ids)
    attempts_by_activity = attempts_used_by_person(db, tenant_id=tenant_id, person_id=person_id)
    grants_by_activity = attempt_policy.granted_by_activity(
        db, tenant_id=tenant_id, person_id=person_id
    )
    due_rows_by_offering = _due_by_offering(db, tenant_id, offering_ids)
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
    # Trend points: every score across the person's courses, ordered, grouped.
    trend_by_course: dict[UUID, list[int]] = {}
    for course_id, fraction in db.execute(
        select(Activity.course_id, Score.fraction)
        .join(Submission, (Submission.id == Score.submission_id) & (Submission.tenant_id == Score.tenant_id))
        .join(Activity, (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id))
        .where(Score.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .where(Activity.course_id.in_(course_ids) if course_ids else Activity.course_id.is_(None))
        .order_by(Score.created_at.asc())
    ).all():
        trend_by_course.setdefault(course_id, []).append(round(100 * fraction))

    out: list[dict] = []
    for course, offering in pairs:
        activities = activities_by_course.get(course.id, [])
        grade = grade_from(activities, best)
        due_by_activity = {
            activity_id: due
            for activity_id, due in due_rows_by_offering.get(offering.id, [])
        }

        rows: list[dict] = []
        upcoming: list[dict] = []
        overdue: list[dict] = []
        for a in activities:
            score = best.get(a.id)
            used = attempts_by_activity.get(a.id, 0)
            ent = attempt_policy.entitlement(
                a, used=used, granted=grants_by_activity.get(a.id, 0)
            )
            remaining = ent.remaining
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
                "max_attempts": ent.limit,
                "attempts_left": remaining,
                "attempts_granted": ent.granted,
                "feedback_available": (
                    score is not None
                    and reveal_feedback(
                        a, passed=score.passed, attempts_used=used,
                        attempts_granted=ent.granted,
                    )
                ),
                "due_at": due,
                "overdue": is_overdue,
            }
            rows.append(row)
            if is_overdue:
                overdue.append(row)
            elif due is not None and due > now and not is_passed:
                upcoming.append(row)

        score_points = trend_by_course.get(course.id, [])[-8:]

        completion = completions.get(course.id)
        certificate = certificates.get(course.id)
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
