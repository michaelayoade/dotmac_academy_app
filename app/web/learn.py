# app/web/learn.py
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Question, Score, Submission
from app.models.course import Chapter, Course
from app.models.person import Person
from app.services.assessment import best_scores_for, submit_activity
from app.services.entitlements import accessible_course_ids, require_course_open
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


def _enrolled_courses(db: Session, tid: UUID, person_id: UUID) -> list[Course]:
    """Courses the person can study, resolved Enrollment -> CourseOffering -> Course.

    Access requires an explicit CourseOffering linking the person's cohort to the
    course; sharing a ``discipline`` string no longer grants access.
    """
    course_ids = accessible_course_ids(db, tenant_id=tid, person_id=person_id)
    if not course_ids:
        return []
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tid)
            .where(Course.id.in_(course_ids))
            .order_by(Course.title)
        ).all()
    )


@router.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Student Learn Home — my courses (completion %), continue, recent results."""
    tenant = require_tenant(request)
    enrolled = _enrolled_courses(db, tenant.id, person.id)

    # My courses: completion % = passed activities / total activities.
    my_courses: list[dict] = []
    best_by_course: dict = {}
    for course in enrolled:
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

    # Continue: first incomplete chapter of the first enrolled course.
    continue_to = None
    for course in enrolled:
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
    recent_rows = db.execute(
        select(Score, Activity.title)
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
        {"title": title, "passed": s.passed, "pct": round(100 * s.fraction)}
        for s, title in recent_rows
    ]

    return templates.TemplateResponse(
        "learn/home.html",
        {
            "request": request,
            "person": person,
            "my_courses": my_courses,
            "continue_to": continue_to,
            "recent": recent,
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
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=course.id)
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
    return templates.TemplateResponse(
        "chapter.html",
        {"request": request, "course": course, "chapter": ch, "activity": act},
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
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)
    qs = db.scalars(
        select(Question)
        .where(Question.tenant_id == tenant.id)
        .where(Question.bank_id == act.bank_id)
    ).all()
    return templates.TemplateResponse(
        "activity.html", {"request": request, "activity": act, "questions": qs}
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
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)
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
        {"request": request, "score": score, "questions": by_id},
    )


@router.get("/progress", response_class=HTMLResponse)
def progress(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    best: dict = {}
    for course in _enrolled_courses(db, tenant.id, person.id):
        best.update(
            best_scores_for(
                db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
            )
        )
    return templates.TemplateResponse(
        "progress.html", {"request": request, "best": list(best.values())}
    )
