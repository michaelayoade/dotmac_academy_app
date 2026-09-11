# app/services/roster.py
"""Cohort roster operations: bulk enrolment and roster-state transitions.

Replaces the one-email-at-a-time enroll that silently no-ops on unknown users.
``bulk_enroll`` reports exactly what happened to each email so the UI can show
which addresses were unknown (candidates for invitation, Slice 3b).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Enrollment
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.identity import person_for_email
from app.services.lookups import cohort_or_404
from app.services.tracks import assign_enrollment_track, ensure_track_offerings

ROSTER_STATES = frozenset({"active", "waitlisted", "dropped"})


@dataclass(frozen=True)
class ActivationResult:
    """What :func:`activate_enrollment` actually did to an existing enrollment."""

    outcome: str  # "reactivated" | "already_active"
    previous_status: str | None  # the status it was reactivated FROM; None when already_active


def activate_enrollment(
    db: Session, *, tenant_id: UUID, enrollment: Enrollment, actor_is_admin: bool
) -> ActivationResult:
    """The one place that decides whether an existing enrollment may be
    moved to status="active", and reports what actually happened.

    Returns an :class:`ActivationResult` with outcome "reactivated" (was
    dropped/waitlisted, now active) or "already_active" (no-op) — "enrolled"
    is NOT returned here: this only handles an EXISTING enrollment, callers
    handle brand-new-enrollment creation themselves and call this only in the
    "enrollment already exists" branch.

    Raises ``BadRequestError`` when the target enrollment's role_in_cohort is
    not "student" and ``actor_is_admin`` is False — mirrors the admin gate
    ``app/web/instructor.py::change_roster_state`` already enforces for the
    opposite (drop) direction on the same field. A student-role enrollment
    may always be reactivated by any instructor: dropping a fellow
    instructor's own enrollment silently strips their authoring access
    (``_assigned_course_ids``), so restoring it is the same authorization
    concern in reverse; a plain student enrollment carries no such risk.

    ``tenant_id`` is accepted (unused today) to keep this call-compatible
    with every other tenant-scoped service function and available if a
    future caller needs it (e.g. for an audit write, deliberately out of
    scope for now).
    """
    if enrollment.status == "active":
        return ActivationResult(outcome="already_active", previous_status="active")
    if enrollment.role_in_cohort != "student" and not actor_is_admin:
        raise BadRequestError(
            "only an admin can reactivate a non-student cohort enrollment"
        )
    previous_status = enrollment.status
    enrollment.status = "active"
    return ActivationResult(outcome="reactivated", previous_status=previous_status)


def _normalize_emails(emails) -> list[str]:
    seen: dict[str, None] = {}
    for raw in emails:
        e = (raw or "").strip().lower()
        if e and e not in seen:
            seen[e] = None
    return list(seen)


def bulk_enroll(
    db: Session,
    *,
    tenant_id: UUID,
    cohort_id: UUID,
    emails,
    actor_is_admin: bool,
    track_id: UUID | None = None,
) -> dict:
    """Enroll each email's person into the cohort as an active student.

    Returns {"enrolled", "reactivated", "already_active", "not_found",
    "admin_required"} lists of emails. Unknown emails are reported, never
    silently dropped — and, matching that same per-email-outcome contract, an
    email whose existing enrollment needs an admin to reactivate (see
    :func:`activate_enrollment`) is categorized into "admin_required" and the
    batch continues; it does NOT abort the rest of the emails in the call.

    ``actor_is_admin`` has no default — every caller must state the acting
    instructor's authority, because reactivating an existing non-student
    (e.g. instructor-role) enrollment is admin-only. Unlike
    :func:`activate_enrollment` itself, ``bulk_enroll`` never raises
    ``BadRequestError`` for this case — it is caught here and folded into
    "admin_required" instead.
    """
    cohort_or_404(db, tenant_id=tenant_id, cohort_id=cohort_id)
    if track_id is not None:
        ensure_track_offerings(db, tenant_id=tenant_id, cohort_id=cohort_id, track_id=track_id)
    result: dict[str, list[str]] = {
        "enrolled": [],
        "reactivated": [],
        "already_active": [],
        "not_found": [],
        "admin_required": [],
    }
    for email in _normalize_emails(emails):
        person = person_for_email(db, tenant_id=tenant_id, email=email)
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
            db.add(
                Enrollment(
                    tenant_id=tenant_id,
                    cohort_id=cohort_id,
                    person_id=person.id,
                    track_id=track_id,
                    role_in_cohort="student",
                    status="active",
                )
            )
            result["enrolled"].append(email)
        elif enr.status != "active":
            try:
                activate_enrollment(db, tenant_id=tenant_id, enrollment=enr, actor_is_admin=actor_is_admin)
            except BadRequestError:
                result["admin_required"].append(email)
                continue
            if track_id is not None:
                assign_enrollment_track(
                    db,
                    tenant_id=tenant_id,
                    cohort_id=cohort_id,
                    person_id=person.id,
                    track_id=track_id,
                )
            result["reactivated"].append(email)
        else:
            if track_id is not None and enr.track_id != track_id:
                assign_enrollment_track(
                    db,
                    tenant_id=tenant_id,
                    cohort_id=cohort_id,
                    person_id=person.id,
                    track_id=track_id,
                )
            result["already_active"].append(email)
    db.flush()
    return result


def set_roster_state(db: Session, *, tenant_id: UUID, cohort_id: UUID, person_id: UUID, state: str) -> Enrollment:
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
