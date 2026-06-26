# app/web/instructor.py
"""Instructor portal routes.

All routes are gated by require_web_role("instructor") — students and unauthenticated
users receive 403 or a redirect to /login respectively.

IMPORTANT: no db.commit() calls inside any handler. The get_db dependency manages the
transaction: it does SET LOCAL app.current_tenant (transaction-scoped) and commits
after the response is built. A mid-handler commit would clear that GUC and break RLS.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.models.assessment import Activity, Score, Submission
from app.services.assessment import override_score
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/instructor",
    dependencies=[Depends(require_tenant), Depends(require_web_role("instructor"))],
)


@router.get("/cohorts", response_class=HTMLResponse)
def cohorts_list(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    rows = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all()
    return templates.TemplateResponse(
        "instructor/cohorts.html", {"request": request, "cohorts": rows}
    )


@router.post("/cohorts")
def create_cohort(
    request: Request,
    name: str = Form(...),
    discipline: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    db.add(Cohort(tenant_id=tenant.id, name=name, discipline=discipline, status="active"))
    # No db.commit() here — get_db commits after the response is returned.
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/enroll")
def enroll_student(
    cohort_id: UUID,
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    person = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant.id)
        .where(Person.email == email)
    ).first()
    if person is not None:
        db.add(
            Enrollment(
                tenant_id=tenant.id,
                cohort_id=cohort_id,
                person_id=person.id,
                role_in_cohort="student",
                status="active",
            )
        )
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/results", response_class=HTMLResponse)
def results(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    rows = db.execute(
        select(Person.email, Activity.title, Score)
        .join(
            Submission,
            (Submission.person_id == Person.id)
            & (Submission.tenant_id == Person.tenant_id),
        )
        .join(
            Activity,
            (Activity.id == Submission.activity_id)
            & (Activity.tenant_id == Submission.tenant_id),
        )
        .join(
            Score,
            (Score.submission_id == Submission.id)
            & (Score.tenant_id == Submission.tenant_id),
        )
        .where(Person.tenant_id == tenant.id)
    ).all()
    return templates.TemplateResponse(
        "instructor/results.html", {"request": request, "rows": rows}
    )


@router.post("/scores/{submission_id}/override")
def override(
    submission_id: UUID,
    request: Request,
    score_value: float = Form(...),
    max_score: float = Form(...),
    reason: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    override_score(
        db,
        tenant_id=tenant.id,
        submission_id=submission_id,
        score_value=score_value,
        max_score=max_score,
        reason=reason,
    )
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/results"
        return resp
    return RedirectResponse("/instructor/results", status_code=status.HTTP_303_SEE_OTHER)
