"""Admissions service — application intake and pipeline transitions.

Follows the repo convention: functions take ``db`` + ``tenant_id`` explicitly,
``flush`` but never ``commit`` (the request/CLI owns the transaction), and raise
domain exceptions (``app/services/exceptions.py``) for the router to translate.
Tenant scoping is enforced by RLS; we still pass ``tenant_id`` on writes so the
``WITH CHECK`` policy passes.
"""

from __future__ import annotations

import secrets
from datetime import UTC, date, datetime, timedelta
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.admissions import APPLICANT_STATUSES, Applicant
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.person import Person
from app.models.rbac import PersonRole
from app.models.track import CohortTrack, Track
from app.services import lifecycle, onboarding
from app.services.audit import write_audit_event
from app.services.bootstrap import ensure_roles
from app.services.exceptions import BadRequestError, ConflictError, NotFoundError
from app.services.security import hash_token

VALID_STATUSES = frozenset(APPLICANT_STATUSES)

ADMIN_ACTION_LABELS = {
    "accept": "Accept and invite to onboarding",
    "waitlist": "Move to waitlist",
    "reject": "Reject application",
    "resend_invitation": "Resend invitation",
    "extend_access": "Extend access",
    "reinvite_assessment": "Send a new assessment invitation",
    "reset_assessment": "Reset sitting and send a new invitation",
}

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


# Profile fields the application form may supply. Only these are accepted from a
# public form, so a crafted POST cannot write arbitrary columns.
PROFILE_FIELDS = (
    "date_of_birth",
    "state",
    "city",
    "highest_qualification",
    "field_of_study",
    "years_experience",
    "current_role",
    "has_device",
    "has_internet",
    "can_work_at_height",
    "available_from",
    "heard_from",
    "cv_url",
)


def _apply_profile(applicant: Applicant, profile: dict | None) -> None:
    """Copy supplied profile fields onto the applicant.

    A field the candidate left blank must never wipe one they already gave, so
    None is skipped rather than written.
    """
    if not profile:
        return
    for f in PROFILE_FIELDS:
        v = profile.get(f)
        if v is not None:
            setattr(applicant, f, v)


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
    track_id: UUID | None = None,
    source: str = "website",
    external_ref: str | None = None,
    applied_on: date | None = None,
    profile: dict | None = None,
) -> Applicant:
    """Create (or refresh) an application. Idempotent on (tenant, email).

    A re-application updates the contact details but never regresses an
    in-flight applicant's pipeline status.
    """
    email = email.strip().lower()
    selected_track: Track | None = None
    if track_id is not None:
        if cohort_id is None:
            raise BadRequestError("A cohort is required when selecting a track.")
        selected_track = db.scalars(
            select(Track)
            .join(
                CohortTrack,
                (CohortTrack.tenant_id == Track.tenant_id) & (CohortTrack.track_id == Track.id),
            )
            .join(
                Cohort,
                (Cohort.tenant_id == CohortTrack.tenant_id)
                & (Cohort.id == CohortTrack.cohort_id),
            )
            .where(Track.tenant_id == tenant_id)
            .where(Track.id == track_id)
            .where(Track.status == "active")
            .where(CohortTrack.cohort_id == cohort_id)
            .where(CohortTrack.status == "active")
            .where(Cohort.status == "active")
        ).first()
        if selected_track is None:
            raise BadRequestError("That training track is not open for the selected cohort.")
        program = selected_track.name
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
        if selected_track is not None:
            existing.track_id = selected_track.id
        if external_ref and not existing.external_ref:
            existing.external_ref = external_ref
        _apply_profile(existing, profile)
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
        track_id=selected_track.id if selected_track is not None else None,
        status="applied",
        source=source,
        external_ref=external_ref,
        applied_on=applied_on or date.today(),
    )
    _apply_profile(applicant, profile)
    db.add(applicant)
    try:
        db.flush()
    except IntegrityError as exc:  # concurrent submit for the same email
        db.rollback()
        raise ConflictError("An application with this email already exists.") from exc
    return applicant


def list_applicants(
    db: Session,
    *,
    status: str | None = None,
    cohort_id: UUID | None = None,
    search: str | None = None,
    applied_from: date | None = None,
    applied_to: date | None = None,
    rank_by_score: bool = False,
    include_invalid: bool = False,
) -> list[Applicant]:
    """List applicants (RLS scopes to the current tenant).

    ``cohort_id`` filters to one intake's candidates; ``rank_by_score`` orders
    by entrance-assessment score (best first, un-assessed last) for selection.

    When ranking, sittings that failed the validity gate (``assessment_valid`` is
    false — near-chance score, or submitted too fast to have engaged) are EXCLUDED
    by default. Those carry no signal: ranking them would seat, or reject, people
    on the strength of random clicking. Pass ``include_invalid=True`` to see them
    anyway (e.g. to review who needs a reset).
    """
    stmt = select(Applicant)
    if status is not None:
        if status not in VALID_STATUSES:
            raise BadRequestError(f"Unknown status: {status}")
        stmt = stmt.where(Applicant.status == status)
    if cohort_id is not None:
        stmt = stmt.where(Applicant.cohort_id == cohort_id)
    if search and (term := search.strip()):
        pattern = f"%{term}%"
        stmt = stmt.where(
            or_(
                Applicant.first_name.ilike(pattern),
                Applicant.last_name.ilike(pattern),
                (Applicant.first_name + " " + Applicant.last_name).ilike(pattern),
            )
        )
    if applied_from is not None:
        stmt = stmt.where(Applicant.applied_on >= applied_from)
    if applied_to is not None:
        stmt = stmt.where(Applicant.applied_on <= applied_to)
    if rank_by_score:
        if not include_invalid:
            stmt = stmt.where(Applicant.assessment_valid.is_not(False))
        stmt = stmt.order_by(Applicant.assessment_score.desc().nullslast(), Applicant.created_at.desc())
    else:
        stmt = stmt.order_by(Applicant.applied_on.desc(), Applicant.created_at.desc())
    return list(db.scalars(stmt).all())


def get_applicant(db: Session, *, applicant_id: UUID) -> Applicant:
    applicant = db.get(Applicant, applicant_id)
    if applicant is None:  # missing, or hidden by RLS — same outcome
        raise NotFoundError("Applicant not found.")
    return applicant


def active_intake_choices(db: Session, *, tenant_id: UUID) -> list[dict[str, object]]:
    """Active cohort/track placements an Academy admin may assign."""
    rows = db.execute(
        select(Cohort, Track)
        .join(
            CohortTrack,
            (CohortTrack.tenant_id == Cohort.tenant_id)
            & (CohortTrack.cohort_id == Cohort.id),
        )
        .join(
            Track,
            (Track.tenant_id == CohortTrack.tenant_id)
            & (Track.id == CohortTrack.track_id),
        )
        .where(Cohort.tenant_id == tenant_id)
        .where(Cohort.status == "active")
        .where(CohortTrack.status == "active")
        .where(Track.status == "active")
        .order_by(Track.name, Cohort.name)
    ).all()
    return [
        {
            "value": f"{cohort.id}:{track.id}",
            "cohort_id": cohort.id,
            "track_id": track.id,
            "cohort": cohort.name,
            "track": track.name,
        }
        for cohort, track in rows
    ]


def _active_intake_track(
    db: Session,
    *,
    tenant_id: UUID,
    cohort_id: UUID | None,
    track_id: UUID | None,
) -> Track | None:
    if cohort_id is None or track_id is None:
        return None
    return db.scalars(
        select(Track)
        .join(
            CohortTrack,
            (CohortTrack.tenant_id == Track.tenant_id)
            & (CohortTrack.track_id == Track.id),
        )
        .join(
            Cohort,
            (Cohort.tenant_id == CohortTrack.tenant_id)
            & (Cohort.id == CohortTrack.cohort_id),
        )
        .where(Track.tenant_id == tenant_id)
        .where(Track.id == track_id)
        .where(Track.status == "active")
        .where(CohortTrack.cohort_id == cohort_id)
        .where(CohortTrack.status == "active")
        .where(Cohort.status == "active")
    ).first()


def has_active_intake(db: Session, *, applicant: Applicant) -> bool:
    return (
        _active_intake_track(
            db,
            tenant_id=applicant.tenant_id,
            cohort_id=applicant.cohort_id,
            track_id=applicant.track_id,
        )
        is not None
    )


def assign_applicant_intake(
    db: Session,
    *,
    applicant_id: UUID,
    cohort_id: UUID,
    track_id: UUID,
    actor_person_id: UUID,
    reason: str | None = None,
) -> Applicant:
    """Assign the canonical cohort/track pair and audit the correction."""
    applicant = db.scalars(
        select(Applicant).where(Applicant.id == applicant_id).with_for_update()
    ).first()
    if applicant is None:
        raise NotFoundError("Applicant not found.")
    track = _active_intake_track(
        db,
        tenant_id=applicant.tenant_id,
        cohort_id=cohort_id,
        track_id=track_id,
    )
    if track is None:
        raise BadRequestError("That cohort and training track are not active.")
    previous_cohort_id = applicant.cohort_id
    previous_track_id = applicant.track_id
    applicant.cohort_id = cohort_id
    applicant.track_id = track_id
    applicant.program = track.name
    db.flush()
    write_audit_event(
        db,
        tenant_id=applicant.tenant_id,
        actor_person_id=actor_person_id,
        action="applicant.intake_assigned",
        entity_type="applicant",
        entity_id=str(applicant.id),
        details={
            "from_cohort_id": str(previous_cohort_id) if previous_cohort_id else "",
            "from_track_id": str(previous_track_id) if previous_track_id else "",
            "to_cohort_id": str(cohort_id),
            "to_track_id": str(track_id),
            "track_name": track.name,
            "reason": reason or "",
            "source": "admin_web",
        },
    )
    return applicant


def admin_review_actions(
    applicant: Applicant,
    *,
    placement_ready: bool | None = None,
) -> list[dict[str, object]]:
    """Backend-owned eligibility for the applicant detail action panel."""
    actions: list[str] = []
    if placement_ready is None:
        placement_ready = applicant.cohort_id is not None and applicant.track_id is not None
    if placement_ready and applicant.status in {"applied", "screened", "waitlisted", "accepted"}:
        actions.append("accept")
    if "waitlisted" in ALLOWED_TRANSITIONS.get(applicant.status, frozenset()):
        actions.append("waitlist")
    if "rejected" in ALLOWED_TRANSITIONS.get(applicant.status, frozenset()):
        actions.append("reject")
    if applicant.assessment_taken_at is not None or applicant.assessment_started_at is not None:
        actions.append("reset_assessment")
    elif applicant.assessment_token_hash is not None:
        actions.append("resend_invitation")
        actions.append("extend_access")
    return [
        {
            "key": action,
            "label": ADMIN_ACTION_LABELS[action],
            "destructive": action in {"reject", "reset_assessment"},
        }
        for action in actions
    ]


def applicant_transition_history(db: Session, *, applicant: Applicant) -> list:
    """Authoritative transition/audit events for one applicant, newest first."""
    from app.models.rbac import AuditEvent

    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == applicant.tenant_id)
            .where(AuditEvent.entity_type == "applicant")
            .where(AuditEvent.entity_id == str(applicant.id))
            .where(
                AuditEvent.action.in_(
                    (
                        "applicant.transition",
                        "applicant.transition_baseline",
                        "applicant.assessment_reset",
                        "applicant.assessment_reinvite",
                        "applicant.invitation_resent",
                        "applicant.access_extended",
                        "applicant.intake_assigned",
                    )
                )
            )
            .order_by(AuditEvent.created_at.desc())
        ).all()
    )



def resend_applicant_invitation(
    db: Session,
    *,
    applicant_id: UUID,
    actor_person_id: UUID,
    base_url: str,
    extend_access: bool = False,
    reason: str | None = None,
) -> Applicant:
    """Resend an external applicant's current invitation through existing services.

    For applicants who have not completed the entrance assessment, the entrance
    assessment invitation is the active access artifact. Reissuing it replaces
    the stored token hash, so older links stop resolving and audit history stays
    append-only.
    """
    from app.services import entrance_exam

    applicant = db.scalars(select(Applicant).where(Applicant.id == applicant_id).with_for_update()).first()
    if applicant is None:
        raise NotFoundError("Applicant not found.")
    if applicant.assessment_taken_at is not None:
        raise BadRequestError("This applicant has already completed the assessment.")
    if not entrance_exam.has_entrance_exam(db, applicant=applicant):
        raise BadRequestError("No entrance assessment is configured for this applicant.")

    previous_deadline = applicant.assessment_deadline
    should_extend = extend_access or previous_deadline is None or entrance_exam.past_deadline(applicant)
    if should_extend:
        entrance_exam.invite(db, applicant=applicant, base_url=base_url)
    else:
        from urllib.parse import quote

        from app.services import applicant_email

        raw = entrance_exam.issue_token(db, applicant=applicant)
        applicant_email.send_exam_invite(
            db,
            applicant=applicant,
            url=f"{base_url.rstrip("/")}/apply/assessment?token={quote(raw)}",
            minutes=entrance_exam.time_limit_minutes(db, applicant=applicant),
        )
    write_audit_event(
        db,
        tenant_id=applicant.tenant_id,
        actor_person_id=actor_person_id,
        action="applicant.invitation_resent",
        entity_type="applicant",
        entity_id=str(applicant.id),
        details={
            "reason": reason or "",
            "source": "admin_web",
            "extended_access": bool(should_extend),
            "previous_assessment_deadline": previous_deadline.isoformat() if previous_deadline else "",
            "assessment_deadline": applicant.assessment_deadline.isoformat() if applicant.assessment_deadline else "",
        },
    )
    return applicant


def extend_applicant_access(
    db: Session,
    *,
    applicant_id: UUID,
    actor_person_id: UUID,
    reason: str | None = None,
) -> Applicant:
    """Extend an uncompleted applicant assessment without changing completed work."""
    from app.services import entrance_exam

    applicant = db.scalars(select(Applicant).where(Applicant.id == applicant_id).with_for_update()).first()
    if applicant is None:
        raise NotFoundError("Applicant not found.")
    if applicant.assessment_taken_at is not None:
        raise BadRequestError("This applicant has already completed the assessment.")
    previous = applicant.assessment_deadline
    applicant.assessment_deadline = datetime.now(UTC) + timedelta(days=entrance_exam.DEFAULT_DEADLINE_DAYS)
    db.flush()
    write_audit_event(
        db,
        tenant_id=applicant.tenant_id,
        actor_person_id=actor_person_id,
        action="applicant.access_extended",
        entity_type="applicant",
        entity_id=str(applicant.id),
        details={
            "reason": reason or "",
            "source": "admin_web",
            "previous_assessment_deadline": previous.isoformat() if previous else "",
            "assessment_deadline": applicant.assessment_deadline.isoformat() if applicant.assessment_deadline else "",
        },
    )
    return applicant

def apply_admin_review_action(
    db: Session,
    *,
    applicant_id: UUID,
    action: str,
    actor_person_id: UUID,
    base_url: str,
    reason: str | None = None,
) -> Applicant:
    """Canonical writer for all applicant-detail actions."""
    applicant = db.scalars(
        select(Applicant).where(Applicant.id == applicant_id).with_for_update()
    ).first()
    if applicant is None:
        raise NotFoundError("Applicant not found.")
    eligible = {
        str(item["key"])
        for item in admin_review_actions(
            applicant,
            placement_ready=has_active_intake(db, applicant=applicant),
        )
    }
    if action not in eligible:
        raise BadRequestError("That action is not available for the applicant's current state.")

    if action == "resend_invitation":
        return resend_applicant_invitation(
            db,
            applicant_id=applicant_id,
            actor_person_id=actor_person_id,
            base_url=base_url,
            extend_access=False,
            reason=reason,
        )

    if action == "extend_access":
        return extend_applicant_access(
            db,
            applicant_id=applicant_id,
            actor_person_id=actor_person_id,
            reason=reason,
        )

    if action == "reset_assessment":
        from app.services import entrance_exam

        entrance_exam.reset_and_invite(db, applicant=applicant, base_url=base_url)
        write_audit_event(
            db,
            tenant_id=applicant.tenant_id,
            actor_person_id=actor_person_id,
            action="applicant.assessment_reset",
            entity_type="applicant",
            entity_id=str(applicant.id),
            details={"reason": reason or "", "source": "admin_web"},
        )
        return applicant

    if action == "reinvite_assessment":
        from app.services import entrance_exam

        entrance_exam.invite(db, applicant=applicant, base_url=base_url)
        write_audit_event(
            db,
            tenant_id=applicant.tenant_id,
            actor_person_id=actor_person_id,
            action="applicant.assessment_reinvite",
            entity_type="applicant",
            entity_id=str(applicant.id),
            details={"reason": reason or "", "source": "admin_web"},
        )
        return applicant

    if action == "accept":
        path = {
            "applied": ("screened", "accepted", "onboarding"),
            "screened": ("accepted", "onboarding"),
            "waitlisted": ("accepted", "onboarding"),
            "accepted": ("onboarding",),
        }[applicant.status]
        for next_status in path:
            transition_applicant(
                db,
                applicant_id=applicant.id,
                to_status=next_status,
                notes=reason,
                actor_person_id=actor_person_id,
                source="admin_web",
            )
        raw = mint_onboarding_token(db, applicant=applicant)
        from app.services import applicant_email

        applicant_email.send_onboarding_invite(
            db,
            applicant=applicant,
            url=f"{base_url.rstrip('/')}/onboarding?token={raw}",
        )
        return applicant

    target = "waitlisted" if action == "waitlist" else "rejected"
    return transition_applicant(
        db,
        applicant_id=applicant.id,
        to_status=target,
        notes=reason,
        actor_person_id=actor_person_id,
        source="admin_web",
    )


def transition_applicant(
    db: Session,
    *,
    applicant_id: UUID,
    to_status: str,
    notes: str | None = None,
    actor_person_id: UUID | None = None,
    source: str = "admin",
) -> Applicant:
    """Move an applicant to ``to_status`` if the transition is allowed."""
    if to_status not in VALID_STATUSES:
        raise BadRequestError(f"Unknown status: {to_status}")

    applicant = db.scalars(
        select(Applicant).where(Applicant.id == applicant_id).with_for_update()
    ).first()
    if applicant is None:
        raise NotFoundError("Applicant not found.")
    current = applicant.status
    if to_status == current:
        return applicant
    if to_status not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise BadRequestError(f"Cannot move applicant from '{current}' to '{to_status}'.")
    if to_status in {"accepted", "onboarding", "enrolled"} and not has_active_intake(
        db,
        applicant=applicant,
    ):
        raise BadRequestError(
            "Assign an active cohort and canonical training track before accepting this applicant."
        )

    applicant.status = to_status
    if notes:
        applicant.notes = notes
    db.flush()
    write_audit_event(
        db,
        tenant_id=applicant.tenant_id,
        actor_person_id=actor_person_id,
        action="applicant.transition",
        entity_type="applicant",
        entity_id=str(applicant.id),
        details={
            "from_status": current,
            "to_status": to_status,
            "reason": notes or "",
            "source": source,
        },
    )
    # Entering onboarding seeds the checklist the applicant must clear to enrol.
    if to_status == "onboarding":
        onboarding.seed_tasks(db, tenant_id=applicant.tenant_id, applicant_id=applicant.id)
        # A completed entrance assessment satisfies its onboarding task (carry-forward).
        if applicant.assessment_taken_at is not None:
            onboarding.complete_task_by_key(
                db, tenant_id=applicant.tenant_id, applicant_id=applicant.id, key="entrance_assessment"
            )
    return applicant


def apply_assessment_policy(db: Session, *, applicant: Applicant) -> str | None:
    """Decide the pipeline consequence of a graded entrance sitting.

    The single owner of the auto-progression decision. Acts only when the
    applicant is still ``applied``, their cohort sets ``auto_accept_threshold``,
    and the sitting passed the validity gate:

    - score >= threshold → screened → accepted → onboarding (portal token
      minted; the raw is returned so the caller can email the offer).
    - score < threshold → waitlisted, for human review of the borderline.
    - invalid sitting / no cohort / no threshold → untouched: a human decides.
    """
    if applicant.status != "applied":
        return None
    if applicant.cohort_id is None or applicant.assessment_score is None:
        return None
    if applicant.assessment_valid is not True:
        return None  # no signal — never auto-decide on an invalid sitting
    cohort = db.get(Cohort, applicant.cohort_id)
    if cohort is None or cohort.auto_accept_threshold is None:
        return None

    score, threshold = applicant.assessment_score, cohort.auto_accept_threshold
    if score >= threshold:
        for nxt in ("screened", "accepted", "onboarding"):
            transition_applicant(
                db,
                applicant_id=applicant.id,
                to_status=nxt,
                source="assessment_policy",
            )
        applicant.notes = f"auto-accepted: entrance score {score:.0%} >= threshold {threshold:.0%}"
        db.flush()
        return mint_onboarding_token(db, applicant=applicant)

    transition_applicant(
        db,
        applicant_id=applicant.id,
        to_status="waitlisted",
        notes=f"auto-waitlisted: entrance score {score:.0%} below threshold {threshold:.0%}",
        source="assessment_policy",
    )
    return None


def mint_onboarding_token(db: Session, *, applicant: Applicant) -> str:
    """Mint (or re-mint) the applicant's self-serve onboarding-portal token.

    Returns the raw token — deliver once (email link); only its hash is stored.
    Re-minting invalidates any older link, same as the entrance-exam invite.
    """
    raw = secrets.token_urlsafe(32)
    applicant.onboarding_token_hash = hash_token(raw)
    db.flush()
    return raw


def applicant_for_onboarding_token(db: Session, *, tenant_id: UUID, raw: str) -> Applicant | None:
    """Resolve an onboarding-portal token to its applicant (None if unknown)."""
    if not raw:
        return None
    return db.scalars(
        select(Applicant)
        .where(Applicant.tenant_id == tenant_id)
        .where(Applicant.onboarding_token_hash == hash_token(raw))
    ).first()


def _ensure_student_role(db: Session, *, tenant_id: UUID, person_id: UUID) -> None:
    roles = ensure_roles(db, tenant_id)
    existing = db.scalars(
        select(PersonRole)
        .where(PersonRole.tenant_id == tenant_id)
        .where(PersonRole.person_id == person_id)
        .where(PersonRole.role_id == roles["student"].id)
    ).first()
    if existing is None:
        db.add(PersonRole(tenant_id=tenant_id, person_id=person_id, role_id=roles["student"].id))
        db.flush()


def try_auto_enroll(db: Session, *, applicant: Applicant) -> tuple[bool, str | None]:
    """Enrol an onboarding applicant the moment their checklist completes.

    No-op unless the applicant is in ``onboarding``, every onboarding task is
    done, and a target cohort is known. On enrolment the Person gets the
    ``student`` role, and — if they have no login credential yet — an invite
    token is issued so they can set their first password.

    Returns ``(enrolled_now, invite_raw)``: ``enrolled_now`` is True only on the
    call that performed the enrolment (so the caller emails the welcome exactly
    once); ``invite_raw`` is the password-setup token to deliver, or None when
    the person already had a credential. Idempotent: re-running never duplicates
    enrolment, role, or credential.
    """
    if applicant.status != "onboarding" or applicant.cohort_id is None:
        return (False, None)
    if not onboarding.is_complete(db, tenant_id=applicant.tenant_id, applicant_id=applicant.id):
        return (False, None)

    enroll_applicant(db, applicant_id=applicant.id, cohort_id=applicant.cohort_id)
    if applicant.person_id is None:  # defensive; enroll_applicant always links it
        return (False, None)
    _ensure_student_role(db, tenant_id=applicant.tenant_id, person_id=applicant.person_id)

    credential = db.scalars(
        select(UserCredential)
        .where(UserCredential.tenant_id == applicant.tenant_id)
        .where(UserCredential.person_id == applicant.person_id)
    ).first()
    if credential is not None:
        return (True, None)
    raw = lifecycle.issue_invite_for_person(db, tenant_id=applicant.tenant_id, person_id=applicant.person_id)
    return (True, raw)


def enroll_applicant(
    db: Session,
    *,
    applicant_id: UUID,
    cohort_id: UUID,
    actor_person_id: UUID | None = None,
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
        raise BadRequestError(f"Applicant must be in 'onboarding' to enrol (is '{applicant.status}').")
    if not onboarding.is_complete(db, tenant_id=applicant.tenant_id, applicant_id=applicant.id):
        raise BadRequestError("Applicant has outstanding onboarding tasks and cannot enrol yet.")

    if applicant.cohort_id != cohort_id:
        raise BadRequestError("Applicant must be enrolled into their assigned cohort.")
    if not has_active_intake(db, applicant=applicant):
        raise BadRequestError("Applicant has no active canonical training track.")

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
                track_id=applicant.track_id,
                person_id=person.id,
                role_in_cohort="student",
                status="active",
            )
        )
        db.flush()
    elif enrollment.track_id != applicant.track_id:
        enrollment.track_id = applicant.track_id
        db.flush()

    applicant.person_id = person.id
    transition_applicant(
        db,
        applicant_id=applicant.id,
        to_status="enrolled",
        actor_person_id=actor_person_id,
        source="admin" if actor_person_id is not None else "onboarding",
    )
    return applicant
