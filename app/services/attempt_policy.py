"""One owner for how many attempts a learner has, and whether they are spent.

Before this module the question "may this learner sit again?" was answered in
five places, each spelling the same expression by hand::

    activity.max_attempts is not None and used >= activity.max_attempts

``assessment.submit_activity`` used it to refuse a submission,
``assessment.reveal_feedback`` to decide whether the answer key may be shown,
``learner_dashboard`` to render "1 of 3 attempts left", ``success_queue`` to
flag a stuck learner, and ``insights`` to report ``attempts_exhausted``. All
five agreed only because none of them had changed yet.

Granting an extra attempt is what breaks that. An entitlement that lives on
``Activity.max_attempts`` alone cannot express "this learner, this activity,
one more go" — so the moment grants exist, every one of those five expressions
is wrong in a different way. The dashboard would promise a retake the submit
path refuses, or the submit path would allow one the answer key had already
been revealed for, which hands back a graded attempt the learner has the
answers to.

So the entitlement is computed here, once, and the five callers ask.

See ``docs/adr/0005-assessment-engine-owns-exam-logic.md`` — this is the same
correction one layer down from selection and validity: a decision with several
implementations drifts as soon as any of them moves.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.attempt import AttemptGrant
from app.services.audit import write_audit_event


@dataclass(frozen=True)
class Entitlement:
    """What a learner may still do on one activity.

    ``limit`` is None for an uncapped activity, in which case nothing is ever
    exhausted and ``remaining`` is None rather than a large number — callers
    render "unlimited", and a number would invite them to count down from it.
    """

    used: int
    granted: int
    limit: int | None

    @property
    def remaining(self) -> int | None:
        if self.limit is None:
            return None
        return max(self.limit - self.used, 0)

    @property
    def exhausted(self) -> bool:
        return self.limit is not None and self.used >= self.limit


def granted_for(db: Session, *, tenant_id: UUID, person_id: UUID, activity_id: UUID) -> int:
    """Extra attempts this learner has been granted on this activity."""
    return int(
        db.scalar(
            select(func.coalesce(func.sum(AttemptGrant.extra_attempts), 0))
            .where(AttemptGrant.tenant_id == tenant_id)
            .where(AttemptGrant.activity_id == activity_id)
            .where(AttemptGrant.person_id == person_id)
        )
        or 0
    )


def granted_by_activity(db: Session, *, tenant_id: UUID, person_id: UUID) -> dict[UUID, int]:
    """Grants per activity for one learner, in ONE grouped query.

    The dashboard and the success queue both render every activity on a course
    at once; asking per activity would turn one page into N queries.
    """
    rows = db.execute(
        select(AttemptGrant.activity_id, func.sum(AttemptGrant.extra_attempts))
        .where(AttemptGrant.tenant_id == tenant_id)
        .where(AttemptGrant.person_id == person_id)
        .group_by(AttemptGrant.activity_id)
    ).all()
    return {activity_id: int(n or 0) for activity_id, n in rows}


def entitlement(activity: Activity, *, used: int, granted: int = 0) -> Entitlement:
    """The pure part: what the limit is, given the counts.

    Separate from the queries so callers that have already batched their counts
    — the dashboard, the success queue — reuse the same arithmetic without
    going back to the database per activity.
    """
    limit = None if activity.max_attempts is None else activity.max_attempts + granted
    return Entitlement(used=used, granted=granted, limit=limit)


def for_learner(
    db: Session, *, tenant_id: UUID, person_id: UUID, activity: Activity, used: int
) -> Entitlement:
    """The entitlement, fetching this learner's grants."""
    granted = granted_for(
        db, tenant_id=tenant_id, person_id=person_id, activity_id=activity.id
    )
    return entitlement(activity, used=used, granted=granted)


def grant_extra_attempt(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    activity_id: UUID,
    reason: str,
    granted_by: UUID | None = None,
    extra_attempts: int = 1,
) -> AttemptGrant:
    """Give a learner more attempts on one activity. The canonical writer.

    ``reason`` is required and not defaulted: a grant reopens a graded
    assessment for one person, and the next administrator to look needs to know
    whether that was a power cut or a favour.
    """
    if extra_attempts < 1:
        raise ValueError("a grant must add at least one attempt")
    if not (reason or "").strip():
        raise ValueError("a grant must record why it was given")

    row = AttemptGrant(
        tenant_id=tenant_id,
        activity_id=activity_id,
        person_id=person_id,
        extra_attempts=extra_attempts,
        reason=reason.strip(),
        granted_by=granted_by,
    )
    db.add(row)
    db.flush()

    # Audited here rather than in the route, so a grant made from the CLI or a
    # future bulk path cannot skip the trail.
    write_audit_event(
        db,
        tenant_id=tenant_id,
        actor_person_id=granted_by,
        action="attempt_granted",
        entity_type="activity",
        entity_id=str(activity_id),
        details={
            "person_id": str(person_id),
            "extra_attempts": extra_attempts,
            "reason": row.reason,
        },
    )
    return row
