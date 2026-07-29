"""Account area — the signed-in user's own profile and password (Task 7).

Every route requires a valid session (``require_web_user``); any logged-in user
(student / instructor / admin) may manage their own account. All queries are
tenant-scoped via ``require_tenant`` + the RLS-bound ``get_db`` session.

IMPORTANT: no ``db.commit()`` inside any handler — ``get_db`` owns the
transaction and commits after the response (a mid-handler commit would clear the
RLS ``app.current_tenant`` GUC).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.models.reminder import EVENT_KINDS
from app.services import reminders as reminders_service
from app.services.roles import role_slugs
from app.services.security import hash_password, verify_password
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])

# Avatar uploads land under the static mount so they serve straight off disk.
AVATAR_ROOT = Path("static/avatars")
# Accepted image types → file extension. Anything else is rejected.
_AVATAR_EXT = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/webp": "webp",
}
MAX_AVATAR_BYTES = 1024 * 1024  # 1 MB


def _flash(request: Request, ok: bool, message: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "account/_flash.html",
        {"request": request, "ok": ok, "message": message},
    )


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
        request,
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
        request,
        "account/_flash.html",
        {"request": request, "ok": True, "message": "Profile updated."},
    )


@router.get("/account/password", response_class=HTMLResponse)
def password_form(
    request: Request,
    person: Person = Depends(require_web_user),
):
    return templates.TemplateResponse(
        request,
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

    if cred is None or not verify_password(current_password, cred.password_hash):
        return _flash(request, False, "Current password is incorrect.")
    if new_password != confirm_password:
        return _flash(request, False, "New passwords do not match.")
    if len(new_password) < 8:
        return _flash(request, False, "New password must be at least 8 characters.")

    cred.password_hash = hash_password(new_password)
    db.flush()
    # No db.commit() here — get_db commits after the response is returned.
    return _flash(request, True, "Password updated.")


@router.post("/account/avatar", response_class=HTMLResponse)
def avatar_upload(
    request: Request,
    file: UploadFile = File(...),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Accept a small image and store it as the person's avatar.

    Saved to ``static/avatars/<tenant_id>/<person_id>.<ext>`` (served off the
    static mount). On success we set ``HX-Refresh`` so the topbar avatar and
    profile preview both pick up the new image. CSRF is enforced by the
    middleware via the htmx ``x-csrf-token`` header (the upload form posts with
    ``hx-encoding="multipart/form-data"``).
    """
    tenant = require_tenant(request)
    ext = _AVATAR_EXT.get((file.content_type or "").lower())
    if ext is None:
        return _flash(request, False, "Please upload a PNG, JPEG, GIF or WebP image.")

    data = file.file.read(MAX_AVATAR_BYTES + 1)
    if not data:
        return _flash(request, False, "The uploaded file was empty.")
    if len(data) > MAX_AVATAR_BYTES:
        return _flash(request, False, "Image too large — please keep it under 1 MB.")

    dest_dir = AVATAR_ROOT / str(tenant.id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Drop any prior avatar (possibly a different extension) so nothing is stale.
    for old in dest_dir.glob(f"{person.id}.*"):
        try:
            old.unlink()
        except OSError:
            pass
    (dest_dir / f"{person.id}.{ext}").write_bytes(data)

    person.avatar_path = f"/static/avatars/{tenant.id}/{person.id}.{ext}"
    db.flush()
    # No db.commit() here — get_db commits after the response is returned.
    resp = _flash(request, True, "Photo updated.")
    resp.headers["HX-Refresh"] = "true"
    return resp


@router.get("/account/notifications", response_class=HTMLResponse)
def notifications_form(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    reminder_pref = reminders_service.get_preference(db, tenant_id=tenant.id, person_id=person.id)
    return templates.TemplateResponse(
        request,
        "account/notifications.html",
        {
            "request": request,
            "person": person,
            "prefs": person.prefs or {},
            "reminder_pref": reminder_pref,
            "reminder_kinds": EVENT_KINDS,
        },
    )


@router.post("/account/reminders", response_class=HTMLResponse)
async def reminders_save(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Persist reminder frequency, quiet hours, and per-event opt-outs.

    Opt-out checkboxes arrive as ``optout_<kind>`` fields; checked means the
    person does NOT want that event kind. Async so the dynamic checkbox names
    can be read from the form body directly.
    """
    tenant = require_tenant(request)
    form = await request.form()
    optouts = [k for k in EVENT_KINDS if form.get(f"optout_{k}")]

    def _hour(raw: object) -> int | None:
        text = str(raw or "").strip()
        return int(text) if text else None

    try:
        reminders_service.save_preference(
            db,
            tenant_id=tenant.id,
            person_id=person.id,
            frequency=str(form.get("frequency", "immediate")),
            quiet_start_hour=_hour(form.get("quiet_start_hour")),
            quiet_end_hour=_hour(form.get("quiet_end_hour")),
            optouts=optouts,
        )
    except ValueError as exc:
        return _flash(request, False, str(exc))
    return _flash(request, True, "Reminder preferences saved.")


@router.post("/account/notifications", response_class=HTMLResponse)
def notifications_save(
    request: Request,
    email_results: str | None = Form(None),
    email_digest: str | None = Form(None),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Persist the per-user email opt-in toggles into ``Person.prefs``.

    Unchecked checkboxes are absent from the form body, so ``None`` => opted out.
    We reassign a NEW dict (not mutate in place) so SQLAlchemy detects the JSONB
    change and writes it back.
    """
    person.prefs = {
        **(person.prefs or {}),
        "email_results": email_results is not None,
        "email_digest": email_digest is not None,
    }
    db.flush()
    # No db.commit() here — get_db commits after the response is returned.
    return _flash(request, True, "Notification preferences saved.")
