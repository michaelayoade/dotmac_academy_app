"""Single owner for account invitation, role, and cohort enrolment decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.rbac import PersonRole
from app.models.track import Track
from app.services import tracks as track_svc
from app.services.bootstrap import ensure_roles
from app.services.exceptions import BadRequestError
from app.services.identity import normalize_email, person_for_email, sync_credential_emails
from app.services.lifecycle import issue_invite_for_person


@dataclass(frozen=True)
class CohortAssignment:
    cohort: Cohort
    courses: tuple[Course, ...] = ()
    track: Track | None = None


@dataclass
class AccountInvitationResult:
    person: Person
    token: str | None
    created_person: bool
    had_credential: bool
    assignments: list[str] = field(default_factory=list)


def _ensure_role(db: Session, *, tenant_id: UUID, person_id: UUID, role: str) -> None:
    roles = ensure_roles(db, tenant_id)
    if role not in roles:
        raise BadRequestError(f"invalid role: {role}")
    grant = db.scalars(
        select(PersonRole)
        .where(PersonRole.tenant_id == tenant_id)
        .where(PersonRole.person_id == person_id)
        .where(PersonRole.role_id == roles[role].id)
    ).first()
    if grant is None:
        db.add(PersonRole(tenant_id=tenant_id, person_id=person_id, role_id=roles[role].id))


def _apply_assignment(
    db: Session,
    *,
    tenant_id: UUID,
    person: Person,
    role: str,
    assignment: CohortAssignment,
) -> list[str]:
    cohort = assignment.cohort
    member_role = "instructor" if role in {"instructor", "admin"} else "student"
    enrollment = db.scalars(
        select(Enrollment)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort.id)
        .where(Enrollment.person_id == person.id)
    ).first()
    if enrollment is None:
        enrollment = Enrollment(
            tenant_id=tenant_id,
            cohort_id=cohort.id,
            person_id=person.id,
            role_in_cohort=member_role,
            status="active",
        )
        db.add(enrollment)
    else:
        enrollment.role_in_cohort = member_role
        enrollment.status = "active"

    descriptions = [f"{cohort.name} cohort as {member_role}"]
    if assignment.track is not None:
        enrollment.track_id = assignment.track.id
        track_svc.ensure_track_offerings(
            db,
            tenant_id=tenant_id,
            cohort_id=cohort.id,
            track_id=assignment.track.id,
        )
        descriptions.append(f"{assignment.track.name} track in {cohort.name}")

    for course in assignment.courses:
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
        descriptions.append(f"{course.title} course for {cohort.name}")
    return descriptions


def invite_and_enroll(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    first_name: str,
    last_name: str,
    role: str,
    assignments: tuple[CohortAssignment, ...] = (),
    now: datetime | None = None,
) -> AccountInvitationResult:
    """Idempotently provision identity, role, enrolment, and activation.

    Existing login-capable users are enrolled without receiving an unusable
    activation link. Credential-less people receive one fresh invite; issuing
    it invalidates any older outstanding invite for the same account.
    """
    canonical = normalize_email(email)
    if not canonical:
        raise BadRequestError("email is required")

    person = person_for_email(db, tenant_id=tenant_id, email=canonical)
    created_person = person is None
    if person is None:
        person = Person(
            tenant_id=tenant_id,
            email=canonical,
            first_name=first_name,
            last_name=last_name,
        )
        db.add(person)
        db.flush()
    else:
        sync_credential_emails(db, person=person)

    _ensure_role(db, tenant_id=tenant_id, person_id=person.id, role=role)
    credentials = db.scalars(
        select(UserCredential).where(UserCredential.tenant_id == tenant_id).where(UserCredential.person_id == person.id)
    ).all()
    had_credential = bool(credentials)

    descriptions: list[str] = []
    for assignment in assignments:
        if assignment.cohort.tenant_id != tenant_id:
            raise BadRequestError("cohort does not belong to this tenant")
        descriptions.extend(
            _apply_assignment(
                db,
                tenant_id=tenant_id,
                person=person,
                role=role,
                assignment=assignment,
            )
        )

    db.flush()
    token = (
        None
        if had_credential
        else issue_invite_for_person(
            db,
            tenant_id=tenant_id,
            person_id=person.id,
            now=now,
        )
    )
    return AccountInvitationResult(
        person=person,
        token=token,
        created_person=created_person,
        had_credential=had_credential,
        assignments=descriptions,
    )
