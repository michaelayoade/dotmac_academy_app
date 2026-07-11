"""Public application + entrance-assessment pages — the fibre-academy intake.

``GET/POST /apply`` records the application; if the chosen cohort has an entrance
assessment configured, the applicant is handed a tokenised link to a self-serve,
one-attempt exam whose result (a competency profile) is stored on the applicant.
Public (no login): tenant resolved from host, RLS primed by ``get_db``; htmx CSRF
via the same cookie→header shim as login.
"""

from __future__ import annotations

import html
from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.admissions import Applicant
from app.models.assessment import Question
from app.models.cohort import Cohort
from app.models.tenant import Tenant
from app.services import admissions as admissions_service
from app.services import applicant_email, entrance_exam
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
    """Cohorts open for intake. If the academy has a tenant-wide default entrance
    bank, every active cohort is open (all applicants sit the exam); otherwise
    only cohorts with their own entrance bank."""
    stmt = select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.status == "active")
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or tenant.default_entrance_bank_id is None:
        stmt = stmt.where(Cohort.entrance_bank_id.isnot(None))
    return list(db.scalars(stmt.order_by(Cohort.name)).all())


def _exam_questions(db: Session, tenant_id: UUID, applicant: Applicant) -> list[Question]:
    bank_id = entrance_exam.resolve_bank_id(db, applicant=applicant)
    return list(
        db.scalars(select(Question).where(Question.tenant_id == tenant_id).where(Question.bank_id == bank_id)).all()
    )


def _exam_view(applicant: Applicant, questions: list[Question]) -> list[dict]:
    """Questions as the candidate sees them: options shuffled per-applicant.

    Deterministic in (applicant, question), so the order is stable across a reload
    or a resumed sitting — otherwise autosaved answers would line up against the
    wrong options.
    """
    return [
        {
            "ext_id": q.ext_id,
            "stem": q.stem,
            "type": q.type,
            "options": entrance_exam.options_for(applicant, q),
        }
        for q in questions
    ]


def _notice(request: Request, title: str, body: str) -> HTMLResponse:
    return templates.TemplateResponse(
        "apply_assessment.html",
        {"request": request, "notice": {"title": title, "body": body}, "questions": None},
    )


@router.get("/apply")
def apply_form(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    return templates.TemplateResponse("apply.html", {"request": request, "cohorts": _open_cohorts(db, tenant.id)})


@router.post("/apply")
def _d(v: str) -> date | None:
    try:
        return date.fromisoformat(v) if v else None
    except ValueError:
        return None


def _i(v: str) -> int | None:
    try:
        return int(v) if v.strip() != "" else None
    except ValueError:
        return None


def _b(v: str) -> bool | None:
    return {"yes": True, "no": False}.get((v or "").strip().lower())


def submit_apply(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(default=""),
    program: str = Form(default="Fiber Academy"),
    cohort_id: str = Form(default=""),
    # --- evaluable profile ---
    date_of_birth: str = Form(default=""),
    state: str = Form(default=""),
    city: str = Form(default=""),
    highest_qualification: str = Form(default=""),
    field_of_study: str = Form(default=""),
    years_experience: str = Form(default=""),
    current_role: str = Form(default=""),
    has_device: str = Form(default=""),
    has_internet: str = Form(default=""),
    can_work_at_height: str = Form(default=""),
    available_from: str = Form(default=""),
    heard_from: str = Form(default=""),
    cv_url: str = Form(default=""),
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
        profile={
            "date_of_birth": _d(date_of_birth),
            "state": state.strip() or None,
            "city": city.strip() or None,
            "highest_qualification": highest_qualification.strip() or None,
            "field_of_study": field_of_study.strip() or None,
            "years_experience": _i(years_experience),
            "current_role": current_role.strip() or None,
            "has_device": _b(has_device),
            "has_internet": _b(has_internet),
            "can_work_at_height": _b(can_work_at_height),
            "available_from": _d(available_from),
            "heard_from": heard_from.strip() or None,
            "cv_url": cv_url.strip() or None,
        },
    )
    safe_name = html.escape((first_name or "").strip()[:80]) or "there"

    applicant_email.send_application_received(db, applicant=applicant)

    if applicant.assessment_taken_at is None and entrance_exam.has_entrance_exam(db, applicant=applicant):
        # Mint the link, set the deadline, and EMAIL it. The link is still shown
        # on-screen so they can start now — but the email is the durable copy, so
        # closing the tab no longer costs them the exam.
        base = str(request.base_url).rstrip("/")
        inv = entrance_exam.invite(db, applicant=applicant, base_url=base)
        return HTMLResponse(
            _START_EXAM.format(name=safe_name, token=html.escape(inv["token"], quote=True))
        )
    return HTMLResponse(_THANKS.format(name=safe_name))


@router.get("/apply/assessment", response_class=HTMLResponse)
def assessment_page(request: Request, token: str = "", db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    applicant = entrance_exam.applicant_for_token(db, tenant_id=tenant.id, raw=token)
    if applicant is None:
        return _notice(request, "Link not valid", "This assessment link is invalid or has expired.")
    if applicant.assessment_taken_at is not None:
        return _notice(request, "Already completed", "You've already completed the entrance assessment. Thank you.")
    if entrance_exam.past_deadline(applicant):
        return _notice(
            request,
            "This assessment has closed",
            "The deadline for your entrance assessment has passed. If you were unable to "
            "sit it in time, contact us and we can reopen it for you.",
        )
    timing = entrance_exam.start_exam(db, applicant=applicant)
    if timing["expired"]:
        return _notice(
            request,
            "Time is up",
            "Your entrance-assessment time has expired. If you were cut off before you "
            "could finish, contact us and we can reopen your sitting.",
        )
    questions = _exam_questions(db, tenant.id, applicant)
    return templates.TemplateResponse(
        "apply_assessment.html",
        {
            "request": request,
            "token": token,
            "questions": _exam_view(applicant, questions),
            # Autosaved progress, so a resumed sitting comes back with answers intact.
            "saved": applicant.assessment_answers or {},
            "remaining_seconds": timing["remaining_seconds"],
            "notice": None,
        },
    )


@router.post("/apply/assessment/save")
async def assessment_autosave(request: Request, db: Session = Depends(get_db)):
    """Autosave in-progress answers (fire-and-forget from the exam page).

    This is what makes a dropped connection survivable: without it the candidate
    loses every answer while the clock keeps running. Always 204 — a failed
    autosave must never interrupt the sitting.
    """
    tenant = require_tenant(request)
    form = await request.form()
    applicant = entrance_exam.applicant_for_token(db, tenant_id=tenant.id, raw=str(form.get("token") or ""))
    if applicant is None or applicant.assessment_taken_at is not None:
        return Response(status_code=204)
    questions = _exam_questions(db, tenant.id, applicant)
    answers = {q.ext_id: form.getlist(q.ext_id) for q in questions}
    entrance_exam.save_answers(db, applicant=applicant, answers=answers)
    return Response(status_code=204)


@router.post("/apply/assessment", response_class=HTMLResponse)
async def assessment_submit(request: Request, token: str = Form(...), db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    applicant = entrance_exam.applicant_for_token(db, tenant_id=tenant.id, raw=token)
    if applicant is None or applicant.assessment_taken_at is not None:
        return _notice(request, "Already completed", "This assessment was already submitted, or the link is invalid.")
    questions = _exam_questions(db, tenant.id, applicant)
    form = await request.form()
    # Start from anything autosaved, then let this submission win where it answered.
    # Matters on the auto-submit at zero, and after a resumed sitting: an answer the
    # candidate gave earlier must not be dropped just because it wasn't re-posted.
    answers: dict[str, list[str]] = dict(applicant.assessment_answers or {})
    for q in questions:
        posted = form.getlist(q.ext_id)
        if posted:
            answers[q.ext_id] = posted
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
