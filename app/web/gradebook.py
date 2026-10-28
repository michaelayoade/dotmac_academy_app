# app/web/gradebook.py
"""Weighted gradebook routes — instructor/admin gated.

Follows the same gating pattern as app/web/reports.py (allows admins who do not
also hold the instructor role). No db.commit() in handlers.
"""
from __future__ import annotations

import csv
import io
from uuid import UUID

import dotmac_learning as learning
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.services.csv_reports import sanitize_cell
from app.services.gradebook import cohort_gradebook
from app.services.gradebook_access import require_gradebook_access
from app.services.identity import AcademyCurrentAccount
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


@router.get("/gradebook", response_class=HTMLResponse)
def gradebook_index(
    request: Request,
    person: AcademyCurrentAccount = Depends(require_gradebook_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cohorts = learning.instructor_cohort_choices(db, tenant_id=tenant.id)
    return templates.TemplateResponse(
        request,
        "instructor/gradebook_index.html", {"request": request, "cohorts": cohorts}
    )


# NOTE: .csv route MUST be registered before /{cohort_id} to avoid the UUID path
# parameter swallowing "<uuid>.csv" — same ordering requirement as reports.py.
@router.get("/gradebook/{cohort_id}.csv")
def gradebook_csv(
    cohort_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_gradebook_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    gb = cohort_gradebook(db, tenant_id=tenant.id, cohort_id=cohort_id)
    activities = gb["activities"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["name", "email", *[sanitize_cell(f"{a.title} (w={a.weight})") for a in activities], "final_pct"]
    )
    for row in gb["rows"]:
        p = row["person"]
        cells = [str(c["pct"]) for c in row["cells"]]
        writer.writerow(
            [sanitize_cell(f"{p.first_name} {p.last_name}".strip()),
             sanitize_cell(row["email"]), *cells, str(row["final_pct"])]
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
    person: AcademyCurrentAccount = Depends(require_gradebook_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    gb = cohort_gradebook(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(
        request,
        "instructor/gradebook.html", {"request": request, **gb}
    )
