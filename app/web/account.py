"""Account area — the signed-in user's own profile and password (Task 7).

Every route requires a valid session (``require_web_user``); any logged-in user
(student / instructor / admin) may manage their own account. All queries are
tenant-scoped via ``require_tenant`` + the RLS-bound ``get_db`` session.

IMPORTANT: no ``db.commit()`` inside any handler — ``get_db`` owns the
transaction and commits after the response (a mid-handler commit would clear the
RLS ``app.current_tenant`` GUC).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.services.roles import role_slugs
from app.services.security import hash_password, verify_password
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


def _cohort_names(db: Session, tenant_id, person_id) -> list[str]:
    return list(
        db.scalars(
            select(Cohort.name)
            .join(
                Enrollment,
                (Enrollment.cohort_id == Cohort.id)
                & (Enrollment.tenant_id == Cohort.tenant_id),
            )
            .where(Cohort.tenant_id == tenant_id)
            .where(Enrollment.person_id == person_id)
            .order_by(Cohort.name)
        ).all()
    )


def _profile_context(request: Request, db: Session, person: Person) -> dict:
    tenant = require_tenant(request)
    return {
        "request": request,
        "person": person,
        "roles": sorted(role_slugs(db, tenant.id, person.id)),
        "cohorts": _cohort_names(db, tenant.id, person.id),
    }


@router.get("/account", response_class=HTMLResponse)
def profile_form(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        "account/profile.html", _profile_context(request, db, person)
    )


@router.post("/account", response_class=HTMLResponse)
def profile_save(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Update first/last name only — email is read-only."""
    person.first_name = first_name
    person.last_name = last_name
    db.flush()
    # No db.commit() here — get_db commits after the response is returned.
    return templates.TemplateResponse(
        "account/_flash.html",
        {"request": request, "ok": True, "message": "Profile updated."},
    )


@router.get("/account/password", response_class=HTMLResponse)
def password_form(
    request: Request,
    person: Person = Depends(require_web_user),
):
    return templates.TemplateResponse(
        "account/password.html", {"request": request, "person": person}
    )


@router.post("/account/password", response_class=HTMLResponse)
def password_change(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cred = db.scalars(
        select(UserCredential)
        .where(UserCredential.tenant_id == tenant.id)
        .where(UserCredential.person_id == person.id)
    ).first()

    def _flash(ok: bool, message: str):
        return templates.TemplateResponse(
            "account/_flash.html",
            {"request": request, "ok": ok, "message": message},
        )

    if cred is None or not verify_password(current_password, cred.password_hash):
        return _flash(False, "Current password is incorrect.")
    if new_password != confirm_password:
        return _flash(False, "New passwords do not match.")
    if len(new_password) < 8:
        return _flash(False, "New password must be at least 8 characters.")

    cred.password_hash = hash_password(new_password)
    db.flush()
    # No db.commit() here — get_db commits after the response is returned.
    return _flash(True, "Password updated.")
