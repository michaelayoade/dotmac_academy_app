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

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.cohort import Cohort
from app.models.person import Person
from app.models.assessment import Activity, Score, Submission
from app.services.assessment import override_score, pending_grading
from app.services.lifecycle import invite_user, set_account_status
from app.services.roster import bulk_enroll, set_roster_state
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


def _split_emails(*fields: str) -> list[str]:
    """Split one or more textarea/CSV email fields into a flat list."""
    out: list[str] = []
    for f in fields:
        for chunk in (f or "").replace(",", "\n").replace(";", "\n").split():
            out.append(chunk)
    return out


@router.post("/cohorts/{cohort_id}/enroll")
def enroll_student(
    cohort_id: UUID,
    request: Request,
    emails: str = Form(""),
    email: str = Form(""),
    db: Session = Depends(get_db),
):
    """Bulk-enroll people by email; reports unknown emails instead of silently
    dropping them (finding #6). Accepts ``emails`` (textarea) and/or ``email``."""
    tenant = require_tenant(request)
    # bulk_enroll raises NotFoundError (-> 404) when the cohort is not in-tenant.
    result = bulk_enroll(
        db, tenant_id=tenant.id, cohort_id=cohort_id,
        emails=_split_emails(emails, email),
    )
    enrolled = len(result["enrolled"]) + len(result["reactivated"])
    summary = f"Enrolled {enrolled}."
    if result["not_found"]:
        summary += " Unknown (not enrolled): " + ", ".join(result["not_found"]) + "."
    if request.headers.get("HX-Request"):
        return HTMLResponse(f'<div class="enroll-summary" role="status">{summary}</div>')
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/roster/{person_id}/state")
def change_roster_state(
    cohort_id: UUID,
    person_id: UUID,
    request: Request,
    state: str = Form(...),
    db: Session = Depends(get_db),
):
    """Drop / waitlist / reactivate a roster member (finding #6)."""
    tenant = require_tenant(request)
    set_roster_state(db, tenant_id=tenant.id, cohort_id=cohort_id, person_id=person_id, state=state)
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/invite")
def invite_to_cohort(
    cohort_id: UUID,
    request: Request,
    email: str = Form(...),
    first_name: str = Form("New"),
    last_name: str = Form("Learner"),
    db: Session = Depends(get_db),
):
    """Invite a new person (no account yet) and enroll them — closes the #6 gap
    where unknown emails were silently dropped. Returns the activation link."""
    tenant = require_tenant(request)
    person, token = invite_user(db, tenant_id=tenant.id, email=email,
                                first_name=first_name, last_name=last_name, role="student")
    bulk_enroll(db, tenant_id=tenant.id, cohort_id=cohort_id, emails=[email])
    link = f"/accept-invite?token={token}"
    return HTMLResponse(
        f'<div class="invite-summary" role="status">Invited {person.email}. '
        f'Activation link: <a href="{link}">{link}</a></div>'
    )


@router.post("/people/{person_id}/status")
def change_account_status(
    person_id: UUID,
    request: Request,
    status_value: str = Form(...),
    db: Session = Depends(get_db),
):
    """Suspend or reactivate a learner account (finding #7)."""
    tenant = require_tenant(request)
    set_account_status(db, tenant_id=tenant.id, person_id=person_id, status=status_value)
    if request.headers.get("HX-Request"):
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


_CSRF_JS = (
    "<script>document.body.addEventListener('htmx:configRequest',function(e){"
    "var m=document.cookie.match(/(?:^|;\\s*)csrf_token=([^;]+)/);"
    "if(m){e.detail.headers['x-csrf-token']=m[1];}});</script>"
)


@router.get("/grading", response_class=HTMLResponse)
def grading_queue(request: Request, db: Session = Depends(get_db)):
    """Manual grading queue: submissions awaiting a score (finding #4)."""
    tenant = require_tenant(request)
    rows = pending_grading(db, tenant_id=tenant.id)
    items = []
    for sub, act, email in rows:
        items.append(
            f"<li class='pending-item' data-submission='{sub.id}'>"
            f"<strong>{act.title}</strong> — {email} (attempt {sub.attempt_no})"
            f"<form hx-post='/instructor/scores/{sub.id}/override' hx-swap='none' "
            f"class='inline-grade'>"
            f"<input name='score_value' type='number' step='0.1' value='0' required>"
            f"<input name='max_score' type='number' step='0.1' value='10' required>"
            f"<input name='reason' value='manual grade' required>"
            f"<button>Save grade</button></form></li>"
        )
    body = "<ul>" + "".join(items) + "</ul>" if items else "<p>Nothing awaiting grading.</p>"
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8><title>Grading queue</title>"
        f"<script src='/static/htmx.min.js' defer></script></head>"
        f"<body><h1>Grading queue</h1>{body}{_CSRF_JS}</body></html>"
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
