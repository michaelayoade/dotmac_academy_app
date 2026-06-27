# app/web/teaching.py
"""Teaching Home — the instructor/admin area landing page (GET /instructor).

Separate router from app/web/instructor.py: that one is gated by
require_web_role("instructor") (exact match), which would lock out an admin who
does not also hold the instructor role. This route instead accepts instructor OR
admin via the same inline gate used by app/web/accounts.py and app/web/reports.py.

Routing note: this router uses prefix="/instructor" with route path "" so it
resolves to exactly "/instructor" and does NOT shadow the other /instructor/*
routes (cohorts, reports, results, labs) on their own routers.

IMPORTANT: no db.commit() inside any handler — get_db owns the transaction and
commits after the response (a mid-handler commit clears the RLS tenant GUC).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.services.roles import role_slugs
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


@router.get("", response_class=HTMLResponse)
def teaching_home(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    if not ({"instructor", "admin"} & role_slugs(db, tenant.id, person.id)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    rows = db.execute(
        select(Cohort, func.count(Enrollment.id))
        .outerjoin(
            Enrollment,
            (Enrollment.cohort_id == Cohort.id)
            & (Enrollment.tenant_id == Cohort.tenant_id),
        )
        .where(Cohort.tenant_id == tenant.id)
        .group_by(Cohort.id)
        .order_by(Cohort.name)
    ).all()
    cohorts = [{"cohort": c, "count": n} for c, n in rows]

    return templates.TemplateResponse(
        "teaching/home.html", {"request": request, "cohorts": cohorts}
    )
