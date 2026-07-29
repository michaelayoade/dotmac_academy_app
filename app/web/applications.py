"""Admin applications page - stored applicant intake records."""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.admissions import APPLICANT_STATUSES
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
