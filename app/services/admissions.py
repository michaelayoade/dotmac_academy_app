"""Admissions service — application intake and pipeline transitions.

Follows the repo convention: functions take ``db`` + ``tenant_id`` explicitly,
``flush`` but never ``commit`` (the request/CLI owns the transaction), and raise
domain exceptions (``app/services/exceptions.py``) for the router to translate.
Tenant scoping is enforced by RLS; we still pass ``tenant_id`` on writes so the
``WITH CHECK`` policy passes.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.admissions import APPLICANT_STATUSES, Applicant
from app.services.exceptions import BadRequestError, ConflictError, NotFoundError

VALID_STATUSES = frozenset(APPLICANT_STATUSES)

# Allowed forward/off-ramp transitions. Accept routes into ``onboarding`` (the
# onboarding workflow lands in P2); ``enrolled`` and ``rejected`` are terminal.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "applied": frozenset({"screened", "rejected", "waitlisted"}),
    "screened": frozenset({"accepted", "rejected", "waitlisted"}),
    "waitlisted": frozenset({"screened", "accepted", "rejected"}),
    "accepted": frozenset({"onboarding", "rejected"}),
    "onboarding": frozenset({"enrolled", "rejected"}),
    "enrolled": frozenset(),
    "rejected": frozenset(),
}


def submit_application(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    first_name: str,
    last_name: str,
    phone: str | None = None,
    program: str | None = None,
    source: str = "website",
    external_ref: str | None = None,
    applied_on: date | None = None,
) -> Applicant:
    """Create (or refresh) an application. Idempotent on (tenant, email).

    A re-application updates the contact details but never regresses an
    in-flight applicant's pipeline status.
    """
    email = email.strip().lower()
    existing = db.scalar(
        select(Applicant).where(Applicant.email == email)  # RLS scopes to tenant
    )
    if existing is not None:
        existing.first_name = first_name.strip()
        existing.last_name = last_name.strip()
        if phone:
            existing.phone = phone.strip()
        if program:
            existing.program = program.strip()
        if external_ref and not existing.external_ref:
            existing.external_ref = external_ref
        db.flush()
        return existing

    applicant = Applicant(
        tenant_id=tenant_id,
        email=email,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        phone=phone.strip() if phone else None,
        program=program.strip() if program else None,
        status="applied",
        source=source,
        external_ref=external_ref,
        applied_on=applied_on or date.today(),
    )
    db.add(applicant)
    try:
        db.flush()
    except IntegrityError as exc:  # concurrent submit for the same email
        db.rollback()
        raise ConflictError("An application with this email already exists.") from exc
    return applicant


def list_applicants(db: Session, *, status: str | None = None) -> list[Applicant]:
    """List applicants (RLS scopes to the current tenant), newest first."""
    stmt = select(Applicant)
    if status is not None:
        if status not in VALID_STATUSES:
            raise BadRequestError(f"Unknown status: {status}")
        stmt = stmt.where(Applicant.status == status)
    stmt = stmt.order_by(Applicant.applied_on.desc(), Applicant.created_at.desc())
    return list(db.scalars(stmt).all())


def get_applicant(db: Session, *, applicant_id: UUID) -> Applicant:
    applicant = db.get(Applicant, applicant_id)
    if applicant is None:  # missing, or hidden by RLS — same outcome
        raise NotFoundError("Applicant not found.")
    return applicant


def transition_applicant(
    db: Session,
    *,
    applicant_id: UUID,
    to_status: str,
    notes: str | None = None,
) -> Applicant:
    """Move an applicant to ``to_status`` if the transition is allowed."""
    if to_status not in VALID_STATUSES:
        raise BadRequestError(f"Unknown status: {to_status}")

    applicant = get_applicant(db, applicant_id=applicant_id)
    current = applicant.status
    if to_status == current:
        return applicant
    if to_status not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise BadRequestError(f"Cannot move applicant from '{current}' to '{to_status}'.")

    applicant.status = to_status
    if notes:
        applicant.notes = notes
    db.flush()
    return applicant
