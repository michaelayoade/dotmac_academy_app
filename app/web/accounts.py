# app/web/accounts.py
"""Account-creation portal routes — create login-capable accounts.

Lives under the /instructor prefix but is a SEPARATE router from
app/web/instructor.py: those routes are gated by require_web_role("instructor")
(exact match), which would lock out an admin who does not also hold the
instructor role. These routes instead accept instructor OR admin.

Gating rules:
  * GET/POST /instructor/users — reachable by instructor OR admin (else 403).
  * POST creating a "student" — any of the above.
  * POST creating an "instructor" or "admin" — requires the actor to be admin.

IMPORTANT: no db.commit() inside any handler — get_db owns the transaction and
commits after the response (a mid-handler commit clears the RLS tenant GUC).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.services.accounts import create_user
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


@router.get("/users", response_class=HTMLResponse)
def users_list(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    slugs = _role_slugs(db, tenant.id, person.id)
    if not ({"instructor", "admin"} & slugs):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    is_admin = "admin" in slugs

    rows = db.execute(
        select(Person.email, Role.slug)
        .join(
            PersonRole,
            (PersonRole.person_id == Person.id)
            & (PersonRole.tenant_id == Person.tenant_id),
        )
        .join(
            Role,
            (Role.id == PersonRole.role_id) & (Role.tenant_id == PersonRole.tenant_id),
        )
        .where(Person.tenant_id == tenant.id)
        .order_by(Person.email)
    ).all()
    return templates.TemplateResponse(
        "instructor/users.html",
        {"request": request, "users": rows, "is_admin": is_admin},
    )


@router.post("/users")
def users_create(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    slugs = _role_slugs(db, tenant.id, person.id)
    if not ({"instructor", "admin"} & slugs):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    # Privilege escalation guard: only admins may mint instructor/admin accounts.
    if role in {"instructor", "admin"} and "admin" not in slugs:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create instructor or admin accounts",
        )

    try:
        create_user(
            db,
            tenant_id=tenant.id,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role=role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    # No db.commit() here — get_db commits after the response is returned.

    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/users"
        return resp
    return RedirectResponse("/instructor/users", status_code=status.HTTP_303_SEE_OTHER)
