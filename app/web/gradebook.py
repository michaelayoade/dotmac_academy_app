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
from app.models.rbac import PersonRole, Role
from app.services.gradebook import cohort_gradebook
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


def _role_slugs(db: Session, tenant_id: UUID, person_id: UUID) -> set[str]:
    rows = db.scalars(
        select(Role.slug)
        .join(PersonRole, (PersonRole.role_id == Role.id) & (PersonRole.tenant_id == Role.tenant_id))
        .where(PersonRole.tenant_id == tenant_id)
        .where(PersonRole.person_id == person_id)
    ).all()
    return set(rows)


def _require_instructor_or_admin(db: Session, tenant_id: UUID, person_id: UUID) -> None:
    if not ({"instructor", "admin"} & _role_slugs(db, tenant_id, person_id)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


@router.get("/gradebook", response_class=HTMLResponse)
def gradebook_index(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    cohorts = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all()
    return templates.TemplateResponse(
        "instructor/gradebook_index.html", {"request": request, "cohorts": cohorts}
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
    _require_instructor_or_admin(db, tenant.id, person.id)
    gb = cohort_gradebook(db, tenant_id=tenant.id, cohort_id=cohort_id)
    activities = gb["activities"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["name", "email", *[f"{a.title} (w={a.weight})" for a in activities], "final_pct"]
    )
    for row in gb["rows"]:
        p = row["person"]
        cells = [str(c["pct"]) for c in row["cells"]]
        writer.writerow(
            [f"{p.first_name} {p.last_name}".strip(), row["email"], *cells, str(row["final_pct"])]
        )

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
    _require_instructor_or_admin(db, tenant.id, person.id)
    gb = cohort_gradebook(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(
        "instructor/gradebook.html", {"request": request, **gb}
    )
