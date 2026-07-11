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
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.services import onboarding
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
    cohort_id: UUID | None = None,
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
        if cohort_id is not None:
            existing.cohort_id = cohort_id
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
        cohort_id=cohort_id,
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
    # Entering onboarding seeds the checklist the applicant must clear to enrol.
    if to_status == "onboarding":
        onboarding.seed_tasks(db, tenant_id=applicant.tenant_id, applicant_id=applicant.id)
        # A completed entrance assessment satisfies its onboarding task (carry-forward).
        if applicant.assessment_taken_at is not None:
            onboarding.complete_task_by_key(
                db, tenant_id=applicant.tenant_id, applicant_id=applicant.id, key="entrance_assessment"
            )
    return applicant


def enroll_applicant(
    db: Session,
    *,
    applicant_id: UUID,
    cohort_id: UUID,
) -> Applicant:
    """Convert an onboarding applicant into an enrolled learner.

    Creates (or reuses) the ``Person`` for this email and enrols them in the
    target cohort as a student, then marks the applicant ``enrolled`` and links
    ``person_id``. Idempotent: an existing person/enrolment is reused, so
    re-running is safe. Requires ``onboarding`` status (the onboarding step
    gates enrolment).
    """
    applicant = get_applicant(db, applicant_id=applicant_id)
    if applicant.status != "onboarding":
        raise BadRequestError(
            f"Applicant must be in 'onboarding' to enrol (is '{applicant.status}')."
        )
    if not onboarding.is_complete(db, tenant_id=applicant.tenant_id, applicant_id=applicant.id):
        raise BadRequestError("Applicant has outstanding onboarding tasks and cannot enrol yet.")

    cohort = db.get(Cohort, cohort_id)
    if cohort is None:  # missing or hidden by RLS
        raise NotFoundError("Cohort not found.")

    # Reuse an existing Person for this email (e.g. an employee already in the
    # tenant), otherwise create one. RLS scopes the lookup to this tenant.
    person = db.scalar(select(Person).where(Person.email == applicant.email))
    if person is None:
        person = Person(
            tenant_id=applicant.tenant_id,
            email=applicant.email,
            first_name=applicant.first_name,
            last_name=applicant.last_name,
        )
        db.add(person)
        db.flush()

    enrollment = db.scalar(
        select(Enrollment).where(
            Enrollment.cohort_id == cohort_id,
            Enrollment.person_id == person.id,
        )
    )
    if enrollment is None:
        db.add(
            Enrollment(
                tenant_id=applicant.tenant_id,
                cohort_id=cohort_id,
                person_id=person.id,
                role_in_cohort="student",
                status="active",
            )
        )
        db.flush()

    applicant.person_id = person.id
    applicant.status = "enrolled"
    db.flush()
    return applicant
