"""Public application + entrance-assessment pages — the fibre-academy intake.

``GET/POST /apply`` records the application; if the chosen cohort has an entrance
assessment configured, the applicant is handed a tokenised link to a self-serve,
one-attempt exam whose result (a competency profile) is stored on the applicant.
Public (no login): tenant resolved from host, RLS primed by ``get_db``; htmx CSRF
via the same cookie→header shim as login.
"""

from __future__ import annotations

import html
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.admissions import Applicant
from app.models.assessment import Question
from app.models.cohort import Cohort
from app.services import admissions as admissions_service
from app.services import entrance_exam
from app.services.exceptions import BadRequestError, NotFoundError
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])

_THANKS = (
    '<div id="apply-result" class="mt-8 rounded-lg border border-brand-200 bg-brand-50 p-6">'
    '<h2 class="font-display text-xl font-[560] text-ink">Application received</h2>'
    '<p class="mt-2 text-sm text-ink-soft">Thanks, {name} — we\'ve got your application '
    "for the Fiber Academy and will reach out by email.</p></div>"
)

_START_EXAM = (
    '<div id="apply-result" class="mt-8 rounded-lg border border-brand-200 bg-brand-50 p-6">'
    '<h2 class="font-display text-xl font-[560] text-ink">Application received — one more step</h2>'
    '<p class="mt-2 text-sm text-ink-soft">Thanks, {name}. Please complete a short entrance '
    "assessment so we can understand your level.</p>"
    '<a class="btn-primary mt-4 inline-block px-4 py-2 text-sm" href="/apply/assessment?token={token}">'
    "Start the assessment</a></div>"
)

_RESULT = (
    '<div id="exam-result" class="rounded-lg border border-brand-200 bg-brand-50 p-6">'
    '<h2 class="font-display text-xl font-[560] text-ink">{title}</h2>'
    '<p class="mt-2 text-sm text-ink-soft">{body}</p></div>'
)


def _open_cohorts(db: Session, tenant_id: UUID) -> list[Cohort]:
    """Active cohorts with an entrance assessment configured (open for intake)."""
    return list(
        db.scalars(
            select(Cohort)
            .where(Cohort.tenant_id == tenant_id)
            .where(Cohort.status == "active")
            .where(Cohort.entrance_bank_id.isnot(None))
            .order_by(Cohort.name)
        ).all()
    )


def _exam_questions(db: Session, tenant_id: UUID, applicant: Applicant) -> list[Question]:
    bank_id = entrance_exam.resolve_bank_id(db, applicant=applicant)
    return list(
        db.scalars(
            select(Question).where(Question.tenant_id == tenant_id).where(Question.bank_id == bank_id)
        ).all()
    )


def _notice(request: Request, title: str, body: str) -> HTMLResponse:
    return templates.TemplateResponse(
        "apply_assessment.html",
        {"request": request, "notice": {"title": title, "body": body}, "questions": None},
    )


@router.get("/apply")
def apply_form(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    return templates.TemplateResponse(
        "apply.html", {"request": request, "cohorts": _open_cohorts(db, tenant.id)}
    )


@router.post("/apply")
def submit_apply(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(default=""),
    program: str = Form(default="Fiber Academy"),
    cohort_id: str = Form(default=""),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    tenant = require_tenant(request)
    cid = UUID(cohort_id) if cohort_id else None
    applicant = admissions_service.submit_application(
        db,
        tenant_id=tenant.id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        phone=phone or None,
        program=program or None,
        cohort_id=cid,
        source="website",
    )
    safe_name = html.escape((first_name or "").strip()[:80]) or "there"

    cohort = db.get(Cohort, cid) if cid else None
    if cohort is not None and cohort.entrance_bank_id is not None and applicant.assessment_taken_at is None:
        token = entrance_exam.issue_token(db, applicant=applicant)
        return HTMLResponse(_START_EXAM.format(name=safe_name, token=html.escape(token, quote=True)))
    return HTMLResponse(_THANKS.format(name=safe_name))


@router.get("/apply/assessment", response_class=HTMLResponse)
def assessment_page(request: Request, token: str = "", db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    applicant = entrance_exam.applicant_for_token(db, tenant_id=tenant.id, raw=token)
    if applicant is None:
        return _notice(request, "Link not valid", "This assessment link is invalid or has expired.")
    if applicant.assessment_taken_at is not None:
        return _notice(request, "Already completed", "You've already completed the entrance assessment. Thank you.")
    return templates.TemplateResponse(
        "apply_assessment.html",
        {"request": request, "token": token, "questions": _exam_questions(db, tenant.id, applicant), "notice": None},
    )


@router.post("/apply/assessment", response_class=HTMLResponse)
async def assessment_submit(request: Request, token: str = Form(...), db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    applicant = entrance_exam.applicant_for_token(db, tenant_id=tenant.id, raw=token)
    if applicant is None or applicant.assessment_taken_at is not None:
        return _notice(request, "Already completed", "This assessment was already submitted, or the link is invalid.")
    questions = _exam_questions(db, tenant.id, applicant)
    form = await request.form()
    answers = {q.ext_id: form.getlist(q.ext_id) for q in questions}
    try:
        entrance_exam.grade_and_record(db, tenant_id=tenant.id, applicant=applicant, answers=answers)
    except (BadRequestError, NotFoundError):
        return HTMLResponse(
            _RESULT.format(title="Could not submit", body="Something went wrong recording your assessment.")
        )
    return HTMLResponse(
        _RESULT.format(
            title="Assessment submitted",
            body="Thank you — your entrance assessment has been recorded. We'll be in touch.",
        )
    )
