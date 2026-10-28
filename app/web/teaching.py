"""Teaching home presentation over public Learning reads; caller owns transaction."""

from __future__ import annotations

import dotmac_learning as learning
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.services.identity import AcademyCurrentAccount
from app.services.success_queue import active_account_selection
from app.services.teaching_access import require_teaching_access
from app.web.pagination import pagination_context
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


@router.get("", response_class=HTMLResponse)
def teaching_home(
    request: Request,
    person: AcademyCurrentAccount = Depends(require_teaching_access),
    db: Session = Depends(get_db),
    limit: int = Query(6, ge=1, le=50),
    offset: int = Query(0, ge=0),
):
    tenant = require_tenant(request)
    summary = learning.instructor_cohorts_summary(
        db, tenant_id=tenant.id, accounts=active_account_selection(tenant.id),
    )
    rows = summary.cohorts
    cohorts = [
        {"cohort": row.cohort, "count": row.active_student_count}
        for row in rows[offset:offset + limit]
    ]
    return templates.TemplateResponse(
        request,
        "teaching/home.html",
        {
            "request": request,
            "cohorts": cohorts,
            "pagination": pagination_context(total=len(rows), limit=limit, offset=offset),
        },
    )
