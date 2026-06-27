# app/web/reports.py
"""Instructor/admin Reports portal — cohort progress matrix, student transcript, CSV.

Read-only views over the assessment ledger (app/services/reports.py).

Gating: instructor OR admin (students get 403). We do NOT use the instructor
router's exact-match require_web_role("instructor") because that locks out admins
who do not also hold the instructor role — same inline gate as app/web/accounts.py.

IMPORTANT: no db.commit() inside any handler — get_db owns the transaction and
commits after the response (a mid-handler commit clears the RLS tenant GUC).
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
from app.services.email import render_cohort_html, render_transcript_html, send_email
from app.services.reports import cohort_matrix, student_transcript
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(prefix="/instructor", dependencies=[Depends(require_tenant)])


def _role_slugs(db: Session, tenant_id: UUID, person_id: UUID) -> set[str]:
    """Return the set of role slugs held by the person within the tenant."""
    rows = db.scalars(
        select(Role.slug)
        .join(
            PersonRole,
            (PersonRole.role_id == Role.id) & (PersonRole.tenant_id == Role.tenant_id),
        )
        .where(PersonRole.tenant_id == tenant_id)
        .where(PersonRole.person_id == person_id)
    ).all()
    return set(rows)


def _require_instructor_or_admin(db: Session, tenant_id: UUID, person_id: UUID) -> None:
    if not ({"instructor", "admin"} & _role_slugs(db, tenant_id, person_id)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


@router.get("/reports", response_class=HTMLResponse)
def reports_index(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    cohorts = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all()
    return templates.TemplateResponse(
        "instructor/reports_index.html", {"request": request, "cohorts": cohorts}
    )


# NOTE: the .csv route MUST be registered before /reports/cohort/{cohort_id}.
# FastAPI compiles {cohort_id} to a greedy [^/]+ matcher, so the plain route would
# otherwise capture "<uuid>.csv" and 422 on UUID validation.
@router.get("/reports/cohort/{cohort_id}.csv")
def reports_cohort_csv(
    cohort_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    matrix = cohort_matrix(db, tenant_id=tenant.id, cohort_id=cohort_id)
    activities = matrix["activities"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "email", *[a.title for a in activities], "completion_pct"])
    for row in matrix["rows"]:
        cells = []
        for a in activities:
            score = row["cells"].get(a.id)
            cells.append(f"{score.fraction:.2f}" if score is not None else "")
        writer.writerow([row["name"], row["email"], *cells, f"{row['completion'] * 100:.0f}"])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cohort-{cohort_id}.csv"},
    )


@router.get("/reports/cohort/{cohort_id}", response_class=HTMLResponse)
def reports_cohort(
    cohort_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    matrix = cohort_matrix(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(
        "instructor/reports_cohort.html", {"request": request, **matrix}
    )


@router.post("/reports/student/{person_id}/email", response_class=HTMLResponse)
def reports_student_email(
    person_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Email the student their transcript; return an htmx flash partial."""
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    transcript = student_transcript(db, tenant_id=tenant.id, person_id=person_id)
    student = transcript["person"]
    sent = send_email(
        student.email,
        f"Your Dotmac Academy transcript — {student.first_name} {student.last_name}".strip(),
        render_transcript_html(transcript),
    )
    return templates.TemplateResponse(
        "instructor/_email_result.html",
        {"request": request, "sent": sent, "to": student.email},
    )


@router.post("/reports/cohort/{cohort_id}/email", response_class=HTMLResponse)
def reports_cohort_email(
    cohort_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Email the requesting instructor the cohort summary; return a flash partial."""
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    matrix = cohort_matrix(db, tenant_id=tenant.id, cohort_id=cohort_id)
    sent = send_email(
        person.email,
        f"Cohort progress — {matrix['cohort'].name}",
        render_cohort_html(matrix),
    )
    return templates.TemplateResponse(
        "instructor/_email_result.html",
        {"request": request, "sent": sent, "to": person.email},
    )


@router.get("/reports/student/{person_id}", response_class=HTMLResponse)
def reports_student(
    person_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _require_instructor_or_admin(db, tenant.id, person.id)
    transcript = student_transcript(db, tenant_id=tenant.id, person_id=person_id)
    return templates.TemplateResponse(
        "instructor/reports_student.html", {"request": request, **transcript}
    )
