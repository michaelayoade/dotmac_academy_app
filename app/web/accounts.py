# app/web/accounts.py
"""Account-creation portal routes — create login-capable accounts.

User management lives in the Admin area (/admin/users) but this is a SEPARATE
router from app/web/settings.py: it is gated inline (instructor OR admin), NOT
by require_web_role("admin"), so an instructor can still view the list and
provision student accounts. Creating an instructor/admin account remains
admin-only (privilege-escalation guard below).

Gating rules:
  * GET/POST /admin/users — reachable by instructor OR admin (else 403).
  * POST creating a "student" — any of the above.
  * POST creating an "instructor" or "admin" — requires the actor to be admin.

IMPORTANT: no db.commit() inside any handler — get_db owns the transaction and
commits after the response (a mid-handler commit clears the RLS tenant GUC).
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.rbac import PersonRole
from app.services.accounts import create_user
from app.services.bootstrap import ensure_roles
from app.services.email import send_email
from app.services.exceptions import ConflictError
from app.services.lifecycle import _issue_token, invite_user, request_password_reset, set_account_status
from app.services.roles import role_slugs
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(prefix="/admin/users", dependencies=[Depends(require_tenant)])


def _role_slugs(db: Session, tenant_id: UUID, person_id: UUID) -> set[str]:
    """Return the set of role slugs held by the person within the tenant.

    Thin wrapper kept for backwards compatibility; delegates to the shared
    `app.services.roles.role_slugs`.
    """
    return role_slugs(db, tenant_id, person_id)


def _html_error(message: str, status_code: int = status.HTTP_200_OK) -> HTMLResponse:
    return HTMLResponse(
        f'<div class="rounded-lg bg-clay-500/15 p-3 text-sm font-semibold text-clay-600">'
        f'{escape(message)}</div>',
        status_code=status_code,
    )


def _cohort_member_role(role: str) -> str:
    return "instructor" if role in {"instructor", "admin"} else "student"


def _ensure_person_role(db: Session, *, tenant_id: UUID, person_id: UUID, role: str) -> None:
    roles = ensure_roles(db, tenant_id)
    if role not in roles:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")
    existing = db.scalars(
        select(PersonRole)
        .where(PersonRole.tenant_id == tenant_id)
        .where(PersonRole.person_id == person_id)
        .where(PersonRole.role_id == roles[role].id)
    ).first()
    if existing is None:
        db.add(PersonRole(tenant_id=tenant_id, person_id=person_id, role_id=roles[role].id))
        db.flush()


def _assign_invited_user(
    db: Session,
    *,
    tenant_id: UUID,
    invited: Person,
    role: str,
    cohorts: list[Cohort],
    courses_by_cohort: dict[UUID, list[Course]],
) -> list[str]:
    assignments: list[str] = []
    if not cohorts:
        return assignments

    member_role = _cohort_member_role(role)
    for cohort in cohorts:
        enrollment = db.scalars(
            select(Enrollment)
            .where(Enrollment.tenant_id == tenant_id)
            .where(Enrollment.cohort_id == cohort.id)
            .where(Enrollment.person_id == invited.id)
        ).first()
        if enrollment is None:
            db.add(
                Enrollment(
                    tenant_id=tenant_id,
                    cohort_id=cohort.id,
                    person_id=invited.id,
                    role_in_cohort=member_role,
                    status="active",
                )
            )
        else:
            enrollment.role_in_cohort = member_role
            enrollment.status = "active"
        assignments.append(f"{cohort.name} cohort as {member_role}")

        for course in courses_by_cohort.get(cohort.id, []):
            offering = db.scalars(
                select(CourseOffering)
                .where(CourseOffering.tenant_id == tenant_id)
                .where(CourseOffering.cohort_id == cohort.id)
                .where(CourseOffering.course_id == course.id)
            ).first()
            if offering is None:
                db.add(
                    CourseOffering(
                        tenant_id=tenant_id,
                        cohort_id=cohort.id,
                        course_id=course.id,
                        status="active",
                    )
                )
            else:
                offering.status = "active"
            assignments.append(f"{course.title} course for {cohort.name}")

    db.flush()
    return assignments


@router.get("", response_class=HTMLResponse)
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

    people = db.scalars(
        select(Person).where(Person.tenant_id == tenant.id).order_by(Person.email)
    ).all()
    cohorts = db.scalars(
        select(Cohort)
        .where(Cohort.tenant_id == tenant.id)
        .where(Cohort.status == "active")
        .order_by(Cohort.name)
    ).all()
    courses = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).order_by(Course.title)
    ).all()
    offering_rows = db.execute(
        select(CourseOffering, Course)
        .join(
            Course,
            (Course.id == CourseOffering.course_id)
            & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .where(CourseOffering.tenant_id == tenant.id)
        .where(CourseOffering.status == "active")
        .order_by(Course.title)
    ).all()
    courses_by_cohort: dict[UUID, list[Course]] = {cohort.id: [] for cohort in cohorts}
    seen_offerings: set[tuple[UUID, UUID]] = set()
    for offering, course in offering_rows:
        key = (offering.cohort_id, course.id)
        if offering.cohort_id in courses_by_cohort and key not in seen_offerings:
            courses_by_cohort[offering.cohort_id].append(course)
            seen_offerings.add(key)
    cohort_course_groups = [
        {"cohort": cohort, "courses": courses_by_cohort.get(cohort.id, [])}
        for cohort in cohorts
    ]
    rows = [
        {
            "person": row,
            "roles": sorted(_role_slugs(db, tenant.id, row.id)),
        }
        for row in people
    ]
    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "users": rows,
            "is_admin": is_admin,
            "cohorts": cohorts,
            "courses": courses,
            "cohort_course_groups": cohort_course_groups,
        },
    )


@router.post("/invite", response_class=HTMLResponse)
def users_invite(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    role: str = Form(...),
    cohort_ids: list[str] = Form([]),
    cohort_id: str = Form(""),
    course_ids: list[str] = Form([]),
    course_id: str = Form(""),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    slugs = _role_slugs(db, tenant.id, person.id)
    if "admin" not in slugs:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can invite users")
    if role not in {"student", "instructor", "admin"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

    cohorts: list[Cohort] = []
    courses_by_cohort: dict[UUID, list[Course]] = {}
    selected_cohort_ids = [raw for raw in [*cohort_ids, cohort_id] if raw]
    selected_course_ids = [raw for raw in [*course_ids, course_id] if raw]
    seen_cohort_ids: set[UUID] = set()
    for raw_cohort_id in selected_cohort_ids:
        try:
            cohort_uuid = UUID(raw_cohort_id)
        except ValueError:
            return _html_error("Invalid cohort selection")
        if cohort_uuid in seen_cohort_ids:
            continue
        cohort = db.scalars(
            select(Cohort)
            .where(Cohort.tenant_id == tenant.id)
            .where(Cohort.id == cohort_uuid)
            .where(Cohort.status == "active")
        ).first()
        if cohort is None:
            return _html_error("Selected cohort was not found")
        seen_cohort_ids.add(cohort_uuid)
        cohorts.append(cohort)
        courses_by_cohort[cohort_uuid] = []
    if selected_course_ids:
        if not cohorts:
            return _html_error("Select at least one cohort before assigning courses")
        seen_course_pairs: set[tuple[UUID, UUID]] = set()
        for raw_course_id in selected_course_ids:
            raw_course_id = raw_course_id.strip()
            target_cohort_ids = list(seen_cohort_ids)
            if ":" in raw_course_id:
                raw_cohort_id, raw_course_uuid = raw_course_id.split(":", 1)
                try:
                    pair_cohort_id = UUID(raw_cohort_id)
                except ValueError:
                    return _html_error("Invalid cohort selection")
                if pair_cohort_id not in seen_cohort_ids:
                    return _html_error("Selected course does not belong to a selected cohort")
                target_cohort_ids = [pair_cohort_id]
            else:
                raw_course_uuid = raw_course_id
            try:
                course_uuid = UUID(raw_course_uuid)
            except ValueError:
                return _html_error("Invalid course selection")
            course = db.scalars(
                select(Course).where(Course.tenant_id == tenant.id).where(Course.id == course_uuid)
            ).first()
            if course is None:
                return _html_error("Selected course was not found")
            for target_cohort_id in target_cohort_ids:
                pair = (target_cohort_id, course_uuid)
                if pair in seen_course_pairs:
                    continue
                seen_course_pairs.add(pair)
                courses_by_cohort.setdefault(target_cohort_id, []).append(course)

    normalized_email = (email or "").strip().lower()
    existing_user = False
    try:
        invited, token = invite_user(
            db,
            tenant_id=tenant.id,
            email=normalized_email,
            first_name=first_name,
            last_name=last_name,
            role=role,
        )
    except ConflictError:
        invited = db.scalars(
            select(Person).where(Person.tenant_id == tenant.id).where(Person.email == normalized_email)
        ).first()
        if invited is None:
            return _html_error("A user with this email already exists")
        existing_user = True
        _ensure_person_role(db, tenant_id=tenant.id, person_id=invited.id, role=role)
        credential = db.scalars(
            select(UserCredential)
            .where(UserCredential.tenant_id == tenant.id)
            .where(UserCredential.person_id == invited.id)
        ).first()
        token = None
        if credential is None:
            token = _issue_token(
                db, tenant_id=tenant.id, person_id=invited.id, kind="invite", now=datetime.now(UTC)
            )

    assignments = _assign_invited_user(
        db,
        tenant_id=tenant.id,
        invited=invited,
        role=role,
        cohorts=cohorts,
        courses_by_cohort=courses_by_cohort,
    )
    link = str(request.url_for("accept_form").include_query_params(token=token)) if token else ""
    assignment_html = ""
    assignment_text = ""
    if assignments:
        assignment_items = "".join(f"<li>{escape(item)}</li>" for item in assignments)
        assignment_html = f"<p>Assignments:</p><ul>{assignment_items}</ul>"
        assignment_text = "\nAssignments: " + "; ".join(assignments) + "\n"
    sent = False
    if token:
        sent = send_email(
            invited.email,
            "You're invited to Dotmac Academy",
            (
                f"<p>Hi {escape(invited.first_name)},</p>"
                f"<p>You have been invited to Dotmac Academy as <strong>{escape(role)}</strong>.</p>"
                f"{assignment_html}"
                f"<p><a href=\"{link}\">Set up your account</a></p>"
                f"<p>If the button does not work, open this link: {link}</p>"
            ),
            text_body=(
                f"Hi {invited.first_name},\n\n"
                f"You have been invited to Dotmac Academy as {role}.\n"
                f"{assignment_text}\n"
                f"Set up your account: {link}\n"
            ),
            db=db,
        )
    if existing_user and token:
        if sent:
            status_text = "User already existed. Invite resent and assignments updated."
        else:
            status_text = "User already existed. Invite link created and assignments updated."
    elif existing_user:
        status_text = "User already exists. Assignments updated."
    else:
        status_text = "Invite sent." if sent else "Invite created. Email was not sent; use this link."
    assignment_status = ""
    if assignments:
        items = "".join(f"<li>{escape(item)}</li>" for item in assignments)
        assignment_status = f'<ul class="mt-1 list-disc pl-5 text-ink-soft">{items}</ul>'
    return HTMLResponse(
        f'<div class="rounded-lg bg-sand-100 p-3 text-sm" role="status">'
        f'<p class="font-semibold">{status_text}</p>'
        f'<p>{escape(invited.email)} - {escape(role)}</p>'
        f'{assignment_status}'
        f'{f'<p><a class="underline" href="{link}">{link}</a></p>' if link else ""}'
        f'</div>'
    )


@router.post("/{person_id}/reset-link", response_class=HTMLResponse)
def users_reset_link(
    person_id: UUID,
    request: Request,
    actor: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    slugs = _role_slugs(db, tenant.id, actor.id)
    if "admin" not in slugs:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can send reset links")
    target = db.scalars(
        select(Person).where(Person.tenant_id == tenant.id).where(Person.id == person_id)
    ).first()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    token = request_password_reset(db, tenant_id=tenant.id, email=target.email)
    if token is None:
        return HTMLResponse(
            (
                '<div class="rounded-lg bg-clay-500/15 p-3 text-sm font-semibold text-clay-600">'
                'No account credential exists yet. Use an invite link instead.</div>'
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    link = str(request.url_for("reset_form").include_query_params(token=token))
    sent = send_email(
        target.email,
        "Reset your Dotmac Academy password",
        (
            f"<p>Hi {target.first_name},</p>"
            f"<p>Use this link to reset your password:</p>"
            f"<p><a href=\"{link}\">Reset password</a></p>"
            f"<p>If the button does not work, open this link: {link}</p>"
        ),
        text_body=f"Reset your Dotmac Academy password: {link}\n",
        db=db,
    )
    status_text = "Reset email sent." if sent else "Reset link created. Email was not sent; use this link."
    return HTMLResponse(
        f'<div class="rounded-lg bg-sand-100 p-3 text-sm" role="status">'
        f'<p class="font-semibold">{status_text}</p>'
        f'<p><a class="underline" href="{link}">{link}</a></p>'
        f'</div>'
    )


@router.post("/{person_id}/status", response_class=HTMLResponse)
def users_status(
    person_id: UUID,
    request: Request,
    status_value: str = Form(...),
    actor: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    slugs = _role_slugs(db, tenant.id, actor.id)
    if "admin" not in slugs:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can manage accounts")
    set_account_status(db, tenant_id=tenant.id, person_id=person_id, status=status_value)
    label = "suspended" if status_value == "suspended" else "reactivated"
    return HTMLResponse(
        (
            '<span class="inline-flex items-center rounded-full bg-brand-100 px-2.5 py-0.5 '
            f'text-xs font-semibold text-brand-800">Account {label}</span>'
        )
    )


@router.post("")
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
        resp.headers["HX-Redirect"] = "/admin/users"
        return resp
    return RedirectResponse("/admin/users", status_code=status.HTTP_303_SEE_OTHER)
