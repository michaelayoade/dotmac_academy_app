"""Admin course access request review panel - GET /admin/course-access-requests."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.person import Person
from app.models.course_access_request import (
    REQUEST_STATUS_APPROVED,
    REQUEST_STATUS_DENIED,
    REQUEST_STATUS_CANCELLED,
    REQUEST_STATUS_PENDING,
)
from app.services.course_access_requests import list_requests, review_request, status_counts
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.web_auth import require_web_role, require_web_user
from app.web.templating import templates

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_tenant), Depends(require_web_role("admin"))],
)

_ALLOWED_STATUSES = {
    REQUEST_STATUS_PENDING,
    REQUEST_STATUS_APPROVED,
    REQUEST_STATUS_DENIED,
    REQUEST_STATUS_CANCELLED,
}


@router.get("/course-access-requests", response_class=HTMLResponse)
def course_access_request_list(
    request: Request,
    db: Session = Depends(get_db),
    status_filter: str | None = Query(None),
) -> HTMLResponse:
    tenant = require_tenant(request)
    if status_filter is not None and status_filter not in _ALLOWED_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status filter.")

    requests = list_requests(
        db, tenant_id=tenant.id, status=status_filter if status_filter in _ALLOWED_STATUSES else None
    )
    counts = status_counts(db, tenant_id=tenant.id)
    total_requests = sum(counts.values())
    return templates.TemplateResponse(
        request,
        "admin/course_access_requests.html",
        {
            "request": request,
            "requests": requests,
            "counts": counts,
            "total_requests": total_requests,
            "status_filter": status_filter or "",
        },
    )


@router.post("/course-access-requests/{request_id}/review", response_class=HTMLResponse)
def course_access_request_review(
    request_id: UUID,
    request: Request,
    status_value: str = Form(...),
    reviewed_reason: str = Form(""),
    db: Session = Depends(get_db),
    actor: Person = Depends(require_web_user),
) -> HTMLResponse:
    tenant = require_tenant(request)
    if status_value not in _ALLOWED_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid decision.")
    try:
        review_request(
            db,
            tenant_id=tenant.id,
            request_id=request_id,
            status=status_value,
            reviewer_person_id=actor.id,
            reviewed_reason=reviewed_reason,
        )
    except (BadRequestError, NotFoundError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RedirectResponse("/admin/course-access-requests", status_code=status.HTTP_303_SEE_OTHER)
