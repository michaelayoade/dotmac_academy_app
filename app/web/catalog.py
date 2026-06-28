# app/web/catalog.py
"""Course catalog web router — /courses and /courses/{slug}."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.course import Course
from app.models.person import Person
from app.services.catalog import (
    all_courses,
    course_completion,
    course_structure,
    my_courses,
)
from app.services.entitlements import require_course_access
from app.services.roles import role_slugs
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])

_STAFF_ROLES = {"instructor", "admin"}


def _is_staff(db: Session, tenant_id: UUID, person_id: UUID) -> bool:
    return bool(_STAFF_ROLES & role_slugs(db, tenant_id, person_id))


@router.get("/courses", response_class=HTMLResponse)
def courses_list(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Catalog index — 'My courses' cards (with completion %) for everyone;
    'All courses' section additionally shown to staff."""
    tenant = require_tenant(request)
    staff = _is_staff(db, tenant.id, person.id)

    enrolled = my_courses(db, tenant_id=tenant.id, person_id=person.id)
    my: list[dict] = [
        {
            "course": c,
            "pct": course_completion(
                db, tenant_id=tenant.id, person_id=person.id, course_id=c.id
            ),
        }
        for c in enrolled
    ]

    all_: list[Course] | None = None
    if staff:
        all_ = all_courses(db, tenant_id=tenant.id)

    return templates.TemplateResponse(
        "learn/courses.html",
        {
            "request": request,
            "person": person,
            "my_courses": my,
            "all_courses": all_,
            "is_staff": staff,
        },
    )


@router.get("/courses/{slug}", response_class=HTMLResponse)
def course_landing(
    slug: str,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Course landing page — Part-grouped structure + Continue CTA.

    Non-enrolled students receive 403; unknown slug 404; staff bypass the
    entitlement check so they can preview any course.
    """
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant.id)
        .where(Course.slug == slug)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)

    staff = _is_staff(db, tenant.id, person.id)
    if not staff:
        # Raises 403 for non-enrolled students.
        require_course_access(
            db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
        )

    structure = course_structure(
        db, tenant_id=tenant.id, person_id=person.id, course=course
    )
    pct = course_completion(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
    )

    return templates.TemplateResponse(
        "learn/course.html",
        {
            "request": request,
            "person": person,
            "course": course,
            "structure": structure,
            "pct": pct,
            "is_staff": staff,
        },
    )
