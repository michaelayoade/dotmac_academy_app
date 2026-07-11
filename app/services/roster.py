# app/services/roster.py
"""Cohort roster operations: bulk enrolment and roster-state transitions.

Replaces the one-email-at-a-time enroll that silently no-ops on unknown users.
``bulk_enroll`` reports exactly what happened to each email so the UI can show
which addresses were unknown (candidates for invitation, Slice 3b).
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Enrollment
from app.models.person import Person
from app.services.exceptions import NotFoundError
from app.services.lookups import cohort_or_404

ROSTER_STATES = frozenset({"active", "waitlisted", "dropped"})


def _normalize_emails(emails) -> list[str]:
    seen: dict[str, None] = {}
    for raw in emails:
        e = (raw or "").strip().lower()
        if e and e not in seen:
            seen[e] = None
    return list(seen)


def bulk_enroll(db: Session, *, tenant_id: UUID, cohort_id: UUID, emails) -> dict:
    """Enroll each email's person into the cohort as an active student.

    Returns {"enrolled", "reactivated", "already_active", "not_found"} lists of
    emails. Unknown emails are reported, never silently dropped.
    """
    cohort_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id)
    result: dict[str, list[str]] = {
        "enrolled": [], "reactivated": [], "already_active": [], "not_found": [],
    }
    for email in _normalize_emails(emails):
        person = db.scalars(
            select(Person).where(Person.tenant_id == tenant_id).where(Person.email == email)
        ).first()
        if person is None:
            result["not_found"].append(email)
            continue
        enr = db.scalars(
            select(Enrollment)
            .where(Enrollment.tenant_id == tenant_id)
            .where(Enrollment.cohort_id == cohort_id)
            .where(Enrollment.person_id == person.id)
        ).first()
        if enr is None:
            db.add(Enrollment(tenant_id=tenant_id, cohort_id=cohort_id, person_id=person.id,
                              role_in_cohort="student", status="active"))
            result["enrolled"].append(email)
        elif enr.status != "active":
            enr.status = "active"
            result["reactivated"].append(email)
        else:
            result["already_active"].append(email)
    db.flush()
    return result


def set_roster_state(db: Session, *, tenant_id: UUID, cohort_id: UUID, person_id: UUID,
                     state: str) -> Enrollment:
    """Transition an enrollment to active | waitlisted | dropped."""
    if state not in ROSTER_STATES:
        raise NotFoundError(f"invalid roster state: {state}")
    enr = db.scalars(
        select(Enrollment)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.person_id == person_id)
    ).first()
    if enr is None:
        raise NotFoundError("enrollment not found")
    enr.status = state
    db.flush()
    return enr
