# app/web/gradebook.py
"""Weighted gradebook routes — instructor/admin gated.

Follows the same gating pattern as app/web/reports.py (allows admins who do not
also hold the instructor role). No db.commit() in handlers.
"""

from __future__ import annotations

import csv
import io
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.cohort import Cohort
from app.models.person import Person
from app.services.facilitator_access import FacilitatorAccess, facilitator_access
from app.services.gradebook import cohort_gradebook
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


def _require_teaching_access(db: Session, *, tenant_id: UUID, person_id: UUID) -> FacilitatorAccess:
    access = facilitator_access(db, tenant_id=tenant_id, person_id=person_id)
    if not access.can_teach:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return access


def _require_cohort_access(db: Session, *, tenant_id: UUID, cohort_id: UUID, access: FacilitatorAccess) -> Cohort:
    cohort = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.id == cohort_id)).first()
    if cohort is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cohort not found")
    if not access.allows_cohort(cohort.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return cohort


@router.get("/gradebook", response_class=HTMLResponse)
def gradebook_index(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    access = _require_teaching_access(db, tenant_id=tenant.id, person_id=person.id)
    if not access.has_global_staff_access and not access.cohort_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    query = select(Cohort).where(Cohort.tenant_id == tenant.id)
    if not access.has_global_staff_access:
        query = query.where(Cohort.id.in_(access.cohort_ids))
    cohorts = db.scalars(query.order_by(Cohort.name)).all()
    return templates.TemplateResponse(
        request, "instructor/gradebook_index.html", {"request": request, "cohorts": cohorts}
    )


# NOTE: .csv route MUST be registered before /{cohort_id} to avoid the UUID path
# parameter swallowing "<uuid>.csv" — same ordering requirement as reports.py.
@router.get("/gradebook/{cohort_id}.csv")
def gradebook_csv(
    cohort_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    access = _require_teaching_access(db, tenant_id=tenant.id, person_id=person.id)
    _require_cohort_access(db, tenant_id=tenant.id, cohort_id=cohort_id, access=access)
    gb = cohort_gradebook(db, tenant_id=tenant.id, cohort_id=cohort_id)
    activities = gb["activities"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "email", *[f"{a.title} (w={a.weight})" for a in activities], "final_pct"])
    for row in gb["rows"]:
        p = row["person"]
        cells = [str(c["pct"]) for c in row["cells"]]
        writer.writerow([f"{p.first_name} {p.last_name}".strip(), row["email"], *cells, str(row["final_pct"])])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=gradebook-{cohort_id}.csv"},
    )


@router.get("/gradebook/{cohort_id}", response_class=HTMLResponse)
def gradebook_cohort(
    cohort_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    access = _require_teaching_access(db, tenant_id=tenant.id, person_id=person.id)
    _require_cohort_access(db, tenant_id=tenant.id, cohort_id=cohort_id, access=access)
    gb = cohort_gradebook(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(request, "instructor/gradebook.html", {"request": request, **gb})
