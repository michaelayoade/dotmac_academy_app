"""Content search web router — GET /search?q=."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.person import Person
from app.services.roles import role_slugs
from app.services.search import search as svc_search
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])

_STAFF_ROLES = {"instructor", "admin"}


@router.get("/search", response_class=HTMLResponse)
def search_page(
    request: Request,
    q: str = "",
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    tenant = require_tenant(request)
    slugs = role_slugs(db, tenant.id, person.id)
    is_staff = bool(_STAFF_ROLES & slugs)
    results = svc_search(db, tenant_id=tenant.id, person_id=person.id, q=q, is_staff=is_staff)
    return templates.TemplateResponse(
        "search.html",
        {
            "request": request,
            "person": person,
            "q": q,
            "courses": results["courses"],
            "chapters": results["chapters"],
        },
    )
