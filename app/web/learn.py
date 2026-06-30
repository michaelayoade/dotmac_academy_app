# app/web/learn.py
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Question, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.course import Chapter, Course
from app.models.person import Person
from app.services.assessment import best_scores_for, submit_activity
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


def _courses(db: Session, tid: UUID) -> list[Course]:
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tid)
            .order_by(Course.title)
        ).all()
    )


def _enrolled_courses(db: Session, tid: UUID, person_id: UUID) -> list[Course]:
    """Courses the person can study, resolved Enrollment -> Cohort -> discipline.

    There is no direct cohort->course link; cohorts and courses share a
    ``discipline`` string, so an active enrollment grants access to every course
    in that discipline.
    """
    disciplines = db.scalars(
        select(Cohort.discipline)
        .join(
            Enrollment,
            (Enrollment.cohort_id == Cohort.id)
            & (Enrollment.tenant_id == Cohort.tenant_id),
        )
        .where(Cohort.tenant_id == tid)
        .where(Enrollment.person_id == person_id)
    ).all()
    if not disciplines:
        return []
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tid)
            .where(Course.discipline.in_(set(disciplines)))
            .where(Course.status.in_(("active", "finished")))
            .order_by(Course.title)
        ).all()
    )


def _course_for_activity(db: Session, tenant_id: UUID, activity: Activity) -> Course:
    course = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant_id)
        .where(Course.id == activity.course_id)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    return course


def _course_is_finished(course: Course) -> bool:
    return course.status == "finished"


@router.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Student Learn Home — my courses (completion %), continue, recent results."""
    tenant = require_tenant(request)
    enrolled = _enrolled_courses(db, tenant.id, person.id)
    active_courses = [course for course in enrolled if course.status == "active"]
    finished_enrolled = [course for course in enrolled if course.status == "finished"]

    # My courses: completion % = passed activities / total activities.
    my_courses: list[dict] = []
    best_by_course: dict = {}
    for course in active_courses:
        total = (
            db.scalar(
                select(func.count())
                .select_from(Activity)
                .where(Activity.tenant_id == tenant.id)
                .where(Activity.course_id == course.id)
            )
            or 0
        )
        best = best_scores_for(
            db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
        )
        best_by_course[course.id] = best
        passed = sum(1 for s in best.values() if s.passed)
        pct = round(100 * passed / total) if total else 0
        my_courses.append(
            {"course": course, "total": total, "passed": passed, "pct": pct}
        )

    finished_courses: list[dict] = []
    for course in finished_enrolled:
        total = (
            db.scalar(
                select(func.count())
                .select_from(Activity)
                .where(Activity.tenant_id == tenant.id)
                .where(Activity.course_id == course.id)
            )
            or 0
        )
        best = best_scores_for(
            db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
        )
        passed = sum(1 for s in best.values() if s.passed)
        pct = round(100 * passed / total) if total else 0
        finished_courses.append(
            {"course": course, "total": total, "passed": passed, "pct": pct}
        )

    # Continue: first incomplete chapter of the first enrolled course.
    continue_to = None
    for course in active_courses:
        passed_acts = {
            aid for aid, s in best_by_course.get(course.id, {}).items() if s.passed
        }
        chapters = db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
            .order_by(Chapter.number)
        ).all()
        for ch in chapters:
            act = db.scalars(
                select(Activity)
                .where(Activity.tenant_id == tenant.id)
                .where(Activity.course_id == course.id)
                .where(Activity.chapter_number == ch.number)
            ).first()
            if act is None or act.id not in passed_acts:
                continue_to = {"course": course, "chapter": ch}
                break
        if continue_to is not None:
            break

    # Recent results: the person's latest few scores (title + pass/fail + %).
    # ``graded`` is False for formative self-checks (pass_threshold == 0, i.e.
    # chapter tests) so the UI shows a neutral "Done" instead of a misleading
    # "Pass" on a low score. Mid/final assessments and labs (threshold > 0) keep
    # Pass/Fail.
    recent_rows = db.execute(
        select(Score, Activity.title, Activity.pass_threshold)
        .join(
            Submission,
            (Submission.id == Score.submission_id)
            & (Submission.tenant_id == Score.tenant_id),
        )
        .join(
            Activity,
            (Activity.id == Submission.activity_id)
            & (Activity.tenant_id == Submission.tenant_id),
        )
        .where(Score.tenant_id == tenant.id)
        .where(Submission.person_id == person.id)
        .order_by(Score.created_at.desc())
        .limit(6)
    ).all()
    recent = [
        {
            "title": title,
            "passed": s.passed,
            "pct": round(100 * s.fraction),
            "graded": (threshold or 0) > 0,
        }
        for s, title, threshold in recent_rows
    ]

    return templates.TemplateResponse(
        "learn/home.html",
        {
            "request": request,
            "person": person,
            "my_courses": my_courses,
            "finished_courses": finished_courses,
            "continue_to": continue_to,
            "recent": recent,
        },
    )


@router.get("/courses/{slug}", response_class=HTMLResponse)
def course_outline(
    slug: str,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Course syllabus: every chapter with its test/lab and the learner's status."""
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).where(Course.slug == slug)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)

    chapters = list(
        db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
            .order_by(Chapter.number)
        ).all()
    )
    activities = list(
        db.scalars(
            select(Activity)
            .where(Activity.tenant_id == tenant.id)
            .where(Activity.course_id == course.id)
        ).all()
    )
    best = best_scores_for(db, tenant_id=tenant.id, person_id=person.id, course_id=course.id)

    acts_by_chapter: dict[int, list] = {}
    for a in activities:
        acts_by_chapter.setdefault(a.chapter_number or 0, []).append(a)

    def _status(a: Activity) -> dict:
        s = best.get(a.id)
        graded = (a.pass_threshold or 0) > 0
        if s is None:
            return {"state": "todo", "label": "Not started"}
        if not graded:
            return {"state": "done", "label": "Done"}
        return {
            "state": "pass" if s.passed else "fail",
            "label": "Pass" if s.passed else "Fail",
        }

    rows = []
    for ch in chapters:
        # Tests before labs within a chapter.
        ch_acts = sorted(
            acts_by_chapter.get(ch.number, []),
            key=lambda a: 0 if a.type == "mcq_test" else 1,
        )
        rows.append(
            {"chapter": ch, "activities": [{"activity": a, "status": _status(a)} for a in ch_acts]}
        )

    # Course-level activities (mid/final assessments) aren't tied to a chapter
    # number, so surface them in their own section instead of dropping them.
    chapter_numbers = {ch.number for ch in chapters}
    extra = [
        {"activity": a, "status": _status(a)}
        for a in sorted(activities, key=lambda a: 0 if a.type == "mcq_test" else 1)
        if (a.chapter_number or 0) not in chapter_numbers
    ]

    total = len(activities)
    passed = sum(1 for s in best.values() if s.passed)
    pct = round(100 * passed / total) if total else 0

    # "Continue" = first chapter with an unattempted activity (else chapter 1).
    continue_n = chapters[0].number if chapters else 1
    for r in rows:
        if r["activities"] and not all(best.get(x["activity"].id) for x in r["activities"]):
            continue_n = r["chapter"].number
            break

    return templates.TemplateResponse(
        "learn/course.html",
        {
            "request": request,
            "course": course,
            "rows": rows,
            "total": total,
            "passed": passed,
            "pct": pct,
            "continue_n": continue_n,
            "extra": extra,
            "course_finished": _course_is_finished(course),
        },
    )


@router.get("/courses/{slug}/chapters/{n}", response_class=HTMLResponse)
def chapter(
    slug: str,
    n: int,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant.id)
        .where(Course.slug == slug)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    ch = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .where(Chapter.number == n)
    ).first()
    if ch is None:
        raise HTTPException(status_code=404)
    act = db.scalars(
        select(Activity)
        .where(Activity.tenant_id == tenant.id)
        .where(Activity.course_id == course.id)
        .where(Activity.chapter_number == n)
    ).first()
    previous_chapter = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .where(Chapter.number < n)
        .order_by(Chapter.number.desc())
    ).first()
    next_chapter = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .where(Chapter.number > n)
        .order_by(Chapter.number)
    ).first()
    total_chapters = int(
        db.scalar(
            select(func.count())
            .select_from(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
        )
        or 0
    )
    return templates.TemplateResponse(
        "chapter.html",
        {
            "request": request,
            "course": course,
            "chapter": ch,
            "activity": act,
            "course_finished": _course_is_finished(course),
            "previous_chapter": previous_chapter,
            "next_chapter": next_chapter,
            "total_chapters": total_chapters,
        },
    )


@router.get("/activities/{activity_id}", response_class=HTMLResponse)
def activity(
    activity_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    act = db.scalars(
        select(Activity)
        .where(Activity.id == activity_id)
        .where(Activity.tenant_id == tenant.id)
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    course = _course_for_activity(db, tenant.id, act)
    if _course_is_finished(course):
        return templates.TemplateResponse(
            "activity.html",
            {
                "request": request,
                "activity": act,
                "course": course,
                "questions": [],
                "course_finished": True,
            },
        )
    qs = db.scalars(
        select(Question)
        .where(Question.tenant_id == tenant.id)
        .where(Question.bank_id == act.bank_id)
    ).all()
    return templates.TemplateResponse(
        "activity.html",
        {
            "request": request,
            "activity": act,
            "course": course,
            "questions": qs,
            "course_finished": False,
        },
    )


@router.post("/activities/{activity_id}/submit", response_class=HTMLResponse)
async def submit(
    activity_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    act = db.scalars(
        select(Activity)
        .where(Activity.id == activity_id)
        .where(Activity.tenant_id == tenant.id)
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    course = _course_for_activity(db, tenant.id, act)
    if _course_is_finished(course):
        raise HTTPException(status_code=403, detail="This course is finished")
    form = await request.form()
    qs = db.scalars(
        select(Question)
        .where(Question.tenant_id == tenant.id)
        .where(Question.bank_id == act.bank_id)
    ).all()
    answers = {q.ext_id: form.getlist(q.ext_id) for q in qs}
    score = submit_activity(
        db,
        tenant_id=tenant.id,
        person_id=person.id,
        activity=act,
        answers=answers,
    )
    # get_db handles the final db.commit(); calling it here would expire all ORM
    # objects (including `qs`) and clear the SET LOCAL tenant config, causing
    # ObjectDeletedError on the lazy-load triggered by by_id construction below.
    by_id = {q.ext_id: q for q in qs}
    return templates.TemplateResponse(
        "_activity_result.html",
        {
            "request": request,
            "score": score,
            "questions": by_id,
            "activity": act,
            "course": course,
        },
    )


@router.get("/progress", response_class=HTMLResponse)
def progress(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    rows: list[dict] = []
    for course in _courses(db, tenant.id):
        activities = {
            activity.id: activity
            for activity in db.scalars(
                select(Activity)
                .where(Activity.tenant_id == tenant.id)
                .where(Activity.course_id == course.id)
            ).all()
        }
        best = best_scores_for(
            db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
        )
        for activity_id, score in best.items():
            activity = activities.get(activity_id)
            if activity is None:
                continue
            rows.append(
                {
                    "course": course,
                    "activity": activity,
                    "score": score,
                    "href": (
                        f"/labs/{activity.id}"
                        if activity.type == "lab"
                        else f"/activities/{activity.id}"
                    ),
                }
            )
    rows.sort(key=lambda row: row["score"].created_at, reverse=True)
    return templates.TemplateResponse(
        "progress.html", {"request": request, "rows": rows}
    )
