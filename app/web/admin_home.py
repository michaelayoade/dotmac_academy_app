# app/web/admin_home.py
"""Admin Console — the admin-area landing page (GET /admin).

Admin only: gated by require_web_role("admin") (exact match), which is correct
here because only admins should ever see the console.

Routing note: this router uses prefix="/admin" with route path "" so it resolves
to exactly "/admin" and does NOT shadow the sibling /admin/settings and
/admin/users routes, which live on their own routers (app/web/settings.py and
app/web/accounts.py) with distinct full paths. Separate routers + distinct full
paths means no shadowing regardless of include order.

IMPORTANT: no db.commit() inside the handler — get_db owns the transaction and
commits after the response (a mid-handler commit clears the RLS tenant GUC).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.cohort import Cohort
from app.models.course import Course
from app.models.lab import LabInstance
from app.models.person import Person
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_tenant), Depends(require_web_role("admin"))],
)


@router.get("", response_class=HTMLResponse)
def admin_console(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)

    def _count(model, *extra):
        stmt = select(func.count()).select_from(model).where(model.tenant_id == tenant.id)
        for clause in extra:
            stmt = stmt.where(clause)
        return db.execute(stmt).scalar_one()

    stats = {
        "people": _count(Person),
        "cohorts": _count(Cohort),
        "courses": _count(Course),
        "labs": _count(LabInstance, LabInstance.status.in_(("active", "provisioning"))),
    }
    return templates.TemplateResponse(
        "admin/console.html", {"request": request, "stats": stats}
    )
