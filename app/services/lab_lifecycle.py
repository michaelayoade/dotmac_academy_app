"""Lab lifecycle service (Task 6): quota-gated request, provision, grade→ledger.

Mirrors ``app/services/assessment.submit_activity`` for the grade path: it
builds a ``Submission`` + ``Score`` directly (no MCQ grader) from the check
engine result so lab attempts flow into the same Score/ledger spine.

Inc1 rule: these functions take ``db`` and ``flush`` only — they NEVER
``commit``. The request handler / CLI owns the transaction boundary.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.assessment import Activity, Score, Submission
from app.models.lab import LabInstance, LabTemplate
from app.services.checks.engine import run_checks
from app.services.lab_seed import generate_seed, interpolate
from app.services.labengine.interface import LabEngine, LabHandle

_ACTIVE_STATUSES = ("provisioning", "active")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def active_count(db: Session, tenant_id) -> int:
    """Count instances currently consuming capacity (provisioning|active)."""
    return int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.tenant_id == tenant_id)
            .where(LabInstance.status.in_(_ACTIVE_STATUSES))
        )
        or 0
    )


def instance_name(tenant_id, person_id, activity_id, n) -> str:
    """Stable, human-traceable instance name: ``dal-<t8>-<p8>-<a8>-<n>``."""
    return f"dal-{str(tenant_id)[:8]}-{str(person_id)[:8]}-{str(activity_id)[:8]}-{n}"


def _attempt_seed_id(person_id, activity_id, n: int) -> int:
    """Deterministic 32-bit PRNG seed, stable per (person, activity, attempt)."""
    h = hashlib.sha256(f"{person_id}:{activity_id}:{n}".encode()).hexdigest()
    return int(h[:8], 16)


def request_lab(db: Session, *, tenant_id, person_id, activity: Activity,
                template: LabTemplate) -> LabInstance:
    """Create a LabInstance for the next attempt — does NOT deploy.

    Queued if at/over ``MAX_CONCURRENT_LABS``, else marked ``provisioning`` for
    the worker to pick up. Seed is generated deterministically per attempt.
    """
    prev = db.scalar(
        select(func.count())
        .select_from(LabInstance)
        .where(LabInstance.tenant_id == tenant_id)
        .where(LabInstance.activity_id == activity.id)
        .where(LabInstance.person_id == person_id)
    )
    n = int(prev or 0) + 1
    seed = generate_seed(template.seed_spec, attempt_id=_attempt_seed_id(person_id, activity.id, n))
    at_capacity = active_count(db, tenant_id) >= settings.max_concurrent_labs
    inst = LabInstance(
        tenant_id=tenant_id,
        activity_id=activity.id,
        person_id=person_id,
        instance_name=instance_name(tenant_id, person_id, activity.id, n),
        seed=seed,
        status="queued" if at_capacity else "provisioning",
        consoles={},
    )
    db.add(inst)
    db.flush()
    return inst


def provision(db: Session, instance: LabInstance, engine: LabEngine,
              template: LabTemplate) -> LabInstance:
    """Deploy the topology for ``instance`` and record consoles / activate it."""
    try:
        topology_text = interpolate(template.topology, instance.seed)
        handle = engine.deploy(topology_text, instance.instance_name)
        instance.consoles = {
            node: {"kind": handle.kinds.get(node), "mgmt": handle.mgmt.get(node)}
            for node in handle.nodes
        }
        instance.status = "active"
        now = _now()
        instance.started_at = now
        instance.last_active_at = now
        instance.error = None
    except Exception as exc:  # surface any deploy failure onto the row
        instance.status = "error"
        instance.error = str(exc)
    db.flush()
    return instance


def grade(db: Session, instance: LabInstance, engine: LabEngine,
          template: LabTemplate, handle: LabHandle) -> Score:
    """Run the template checks against the live instance and write Submission+Score.

    The caller supplies ``handle`` (the live :class:`LabHandle` — see the web/CLI
    callers which reconstruct it via the engine); this keeps grade pure and
    testable. Mirrors ``submit_activity``: ``attempt_no`` = max+1, flush, no commit.
    """
    result = run_checks(template.checks, engine, handle, instance.seed)
    score_val = result["score"]
    max_score = result["max_score"]
    fraction = (score_val / max_score) if max_score else 0.0

    threshold = template.limits.get("pass_threshold")
    if threshold is None:
        act = db.scalars(
            select(Activity)
            .where(Activity.tenant_id == instance.tenant_id)
            .where(Activity.id == instance.activity_id)
        ).first()
        threshold = act.pass_threshold if act is not None else 0.0

    prev = db.scalar(
        select(func.coalesce(func.max(Submission.attempt_no), 0))
        .where(Submission.tenant_id == instance.tenant_id)
        .where(Submission.activity_id == instance.activity_id)
        .where(Submission.person_id == instance.person_id)
    )
    sub = Submission(
        tenant_id=instance.tenant_id,
        activity_id=instance.activity_id,
        person_id=instance.person_id,
        answers={"seed": instance.seed, "instance": str(instance.id)},
        attempt_no=int(prev) + 1,
    )
    db.add(sub)
    db.flush()

    score = Score(
        tenant_id=instance.tenant_id,
        submission_id=sub.id,
        score=score_val,
        max_score=max_score,
        fraction=fraction,
        passed=(max_score > 0 and fraction >= threshold),
        per_item=result["per_check"],
        source="auto",
    )
    db.add(score)
    instance.last_active_at = _now()
    db.flush()
    return score


def reset(db: Session, instance: LabInstance, engine: LabEngine,
          template: LabTemplate) -> LabInstance:
    """Tear down and redeploy the instance topology in place (fresh state)."""
    engine.reset(interpolate(template.topology, instance.seed), instance.instance_name)
    instance.last_active_at = _now()
    db.flush()
    return instance


def destroy(db: Session, instance: LabInstance, engine: LabEngine) -> LabInstance:
    """Destroy the underlying lab and mark the instance ``reaped``."""
    engine.destroy(instance.instance_name)
    instance.status = "reaped"
    db.flush()
    return instance
