# app/web/learn.py
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.course import Course, Chapter
from app.models.assessment import Activity, Question
from app.models.person import Person
from app.services.web_auth import require_web_user
from app.services.assessment import submit_activity, best_scores_for
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


def _foundation(db: Session, tid: UUID) -> Course | None:
    return db.scalars(
        select(Course)
        .where(Course.tenant_id == tid)
        .where(Course.slug == "foundation")
    ).first()


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = _foundation(db, tenant.id)
    chapters = []
    if course:
        chapters = db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
            .order_by(Chapter.order_index)
        ).all()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "person": person, "course": course, "chapters": chapters},
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
    course = _foundation(db, tenant.id)
    best = (
        best_scores_for(db, tenant_id=tenant.id, person_id=person.id, course_id=course.id)
        if course
        else {}
    )
    return templates.TemplateResponse(
        "progress.html", {"request": request, "best": list(best.values())}
    )
