# app/web/teaching.py
"""Teaching Home — the instructor/admin area landing page (GET /instructor).

Separate router from app/web/instructor.py: that one is gated by
require_web_role("instructor") (exact match), which would lock out an admin who
does not also hold the instructor role. This route instead accepts instructor OR
admin via the same inline gate used by app/web/accounts.py and app/web/reports.py.

IMPORTANT: no db.commit() inside handlers — get_db owns the transaction.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.services.facilitator_access import authorized_cohort_ids, facilitator_access
from app.services.web_auth import require_web_user
from app.web.pagination import pagination_context
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


@router.get("", response_class=HTMLResponse)
def teaching_home(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
    limit: int = Query(6, ge=1, le=50),
    offset: int = Query(0, ge=0),
):
    tenant = require_tenant(request)
    access = facilitator_access(db, tenant_id=tenant.id, person_id=person.id)
    if not access.can_teach:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    visible_cohort_ids = authorized_cohort_ids(db, tenant_id=tenant.id, access=access)
    cohort_filter = (
        Cohort.tenant_id == tenant.id if access.has_global_staff_access else Cohort.id.in_(visible_cohort_ids)
    )
    total = int(db.scalar(select(func.count()).select_from(Cohort).where(cohort_filter)) or 0)
    rows = db.execute(
        select(Cohort, func.count(Person.id))
        .outerjoin(
            Enrollment,
            (Enrollment.cohort_id == Cohort.id)
            & (Enrollment.tenant_id == Cohort.tenant_id)
            & (Enrollment.status == "active")
            & (Enrollment.role_in_cohort == "student"),
        )
        .outerjoin(
            Person,
            (Person.id == Enrollment.person_id)
            & (Person.tenant_id == Enrollment.tenant_id)
            & (Person.status == "active"),
        )
        .where(Cohort.tenant_id == tenant.id)
        .where(cohort_filter)
        .group_by(Cohort.id)
        .order_by(Cohort.name)
        .limit(limit)
        .offset(offset)
    ).all()
    cohorts = [{"cohort": cohort, "count": count} for cohort, count in rows]

    return templates.TemplateResponse(
        request,
        "teaching/home.html",
        {
            "request": request,
            "cohorts": cohorts,
            "pagination": pagination_context(total=total, limit=limit, offset=offset),
            "has_global_staff_access": access.has_global_staff_access,
            "has_cohort_scope": access.has_global_staff_access or bool(access.cohort_ids),
        },
    )
