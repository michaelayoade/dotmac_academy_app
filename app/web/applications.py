"""Admin applications page - stored applicant intake records."""

from __future__ import annotations

from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.admissions import APPLICANT_STATUSES
from app.models.person import Person
from app.services import admissions as admissions_service
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/admin/applications",
    dependencies=[Depends(require_tenant), Depends(require_web_role("admin"))],
)


def _parse_optional_date(value: str | None, field: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {field} date.") from exc


@router.get("", response_class=HTMLResponse)
def applications_page(
    request: Request,
    status: str | None = Query(default=None),
    q: str | None = Query(default=None),
    applied_from: str | None = Query(default=None),
    applied_to: str | None = Query(default=None),
    rank: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    from_date = _parse_optional_date(applied_from, "from")
    to_date = _parse_optional_date(applied_to, "to")
    filter_error = None
    if from_date is not None and to_date is not None and from_date > to_date:
        filter_error = "Start date must be before or the same as end date."
        applicants = []
    else:
        applicants = admissions_service.list_applicants(
            db,
            status=status or None,
            search=q or None,
            applied_from=from_date,
            applied_to=to_date,
            rank_by_score=rank,
        )
    return templates.TemplateResponse(
        request,
        "admin/applications.html",
        {
            "request": request,
            "applicants": applicants,
            "filter_error": filter_error,
            "statuses": APPLICANT_STATUSES,
            "selected_status": status or "",
            "search_query": q or "",
            "applied_from": from_date.isoformat() if from_date else "",
            "applied_to": to_date.isoformat() if to_date else "",
            "rank": rank,
        },
    )


@router.get("/{applicant_id}", response_class=HTMLResponse)
def application_detail(
    applicant_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    applicant = admissions_service.get_applicant(db, applicant_id=applicant_id)
    return templates.TemplateResponse(
        request,
        "admin/application_detail.html",
        {
            "request": request,
            "applicant": applicant,
            "actions": admissions_service.admin_review_actions(
                applicant,
                placement_ready=admissions_service.has_active_intake(
                    db,
                    applicant=applicant,
                ),
            ),
            "intake_choices": admissions_service.active_intake_choices(
                db,
                tenant_id=applicant.tenant_id,
            ),
            "history": admissions_service.applicant_transition_history(db, applicant=applicant),
        },
    )


@router.post("/{applicant_id}/intake")
def application_intake(
    applicant_id: UUID,
    request: Request,
    intake_choice: str = Form(...),
    reason: str = Form(""),
    actor: Person = Depends(require_web_role("admin")),
    db: Session = Depends(get_db),
):
    try:
        cohort_raw, track_raw = intake_choice.split(":", 1)
        cohort_id, track_id = UUID(cohort_raw), UUID(track_raw)
    except (AttributeError, ValueError):
        raise HTTPException(status_code=400, detail="Choose an active cohort and track.") from None
    admissions_service.assign_applicant_intake(
        db,
        applicant_id=applicant_id,
        cohort_id=cohort_id,
        track_id=track_id,
        actor_person_id=actor.id,
        reason=reason.strip() or None,
    )
    return RedirectResponse(f"/admin/applications/{applicant_id}", status_code=303)


@router.post("/{applicant_id}/action")
def application_action(
    applicant_id: UUID,
    request: Request,
    action: str = Form(...),
    reason: str = Form(""),
    actor: Person = Depends(require_web_role("admin")),
    db: Session = Depends(get_db),
):
    admissions_service.apply_admin_review_action(
        db,
        applicant_id=applicant_id,
        action=action,
        actor_person_id=actor.id,
        base_url=str(request.base_url).rstrip("/"),
        reason=reason.strip() or None,
    )
    return RedirectResponse(f"/admin/applications/{applicant_id}", status_code=303)
