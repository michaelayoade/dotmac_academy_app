"""Admin applications page - stored applicant intake records."""

from __future__ import annotations

import csv
import io
from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.admissions import APPLICANT_STATUSES, Applicant
from app.models.person import Person
from app.services import admissions as admissions_service
from app.services import csv_reports
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


def _filtered_applicants(
    db: Session,
    *,
    status: str | None,
    q: str | None,
    applied_from: str | None,
    applied_to: str | None,
    rank: bool,
) -> tuple[list[Applicant], str | None, date | None, date | None]:
    from_date = _parse_optional_date(applied_from, "from")
    to_date = _parse_optional_date(applied_to, "to")
    if from_date is not None and to_date is not None and from_date > to_date:
        return [], "Start date must be before or the same as end date.", from_date, to_date
    return (
        admissions_service.list_applicants(
            db,
            status=status or None,
            search=q or None,
            applied_from=from_date,
            applied_to=to_date,
            rank_by_score=rank,
        ),
        None,
        from_date,
        to_date,
    )


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
    applicants, filter_error, from_date, to_date = _filtered_applicants(
        db,
        status=status,
        q=q,
        applied_from=applied_from,
        applied_to=applied_to,
        rank=rank,
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


def _format_date(value: object) -> str:
    return value.isoformat() if value else ""


def _format_bool(value: bool | None) -> str:
    if value is None:
        return ""
    return "true" if value else "false"


def _applicants_csv(applicants: list[Applicant]) -> str:
    headers = [
        "name",
        "email",
        "phone",
        "program",
        "status",
        "applied_on",
        "assessment_score_pct",
        "assessment_level",
        "assessment_taken_at",
        "assessment_valid",
        "assessment_invalid_reason",
        "profile_complete",
        "missing_profile_fields",
        "state",
        "city",
        "highest_qualification",
        "years_experience",
        "has_device",
        "has_internet",
        "available_from",
        "heard_from",
        "cv_url",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow([csv_reports.sanitize_cell(c) for c in headers])
    for applicant in applicants:
        score_pct = (
            f"{applicant.assessment_score * 100:.0f}"
            if applicant.assessment_score is not None
            else ""
        )
        row = [
            f"{applicant.first_name} {applicant.last_name}".strip(),
            applicant.email,
            applicant.phone or "",
            applicant.program or "",
            applicant.status,
            _format_date(applicant.applied_on),
            score_pct,
            applicant.assessment_level or "",
            _format_date(applicant.assessment_taken_at),
            _format_bool(applicant.assessment_valid),
            applicant.assessment_invalid_reason or "",
            _format_bool(applicant.profile_complete),
            ";".join(applicant.missing_profile_fields),
            applicant.state or "",
            applicant.city or "",
            applicant.highest_qualification or "",
            applicant.years_experience if applicant.years_experience is not None else "",
            _format_bool(applicant.has_device),
            _format_bool(applicant.has_internet),
            _format_date(applicant.available_from),
            applicant.heard_from or "",
            applicant.cv_url or "",
        ]
        writer.writerow([csv_reports.sanitize_cell(c) for c in row])
    return buf.getvalue()


@router.get("/export.csv")
def applications_export_csv(
    status: str | None = Query(default=None),
    q: str | None = Query(default=None),
    applied_from: str | None = Query(default=None),
    applied_to: str | None = Query(default=None),
    rank: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    applicants, _, _, _ = _filtered_applicants(
        db,
        status=status,
        q=q,
        applied_from=applied_from,
        applied_to=applied_to,
        rank=rank,
    )
    filename = f"applicants_export_{date.today().isoformat()}.csv"
    return Response(
        content=_applicants_csv(applicants),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{applicant_id:uuid}", response_class=HTMLResponse)
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


@router.post("/{applicant_id:uuid}/intake")
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


@router.post("/{applicant_id:uuid}/action")
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
