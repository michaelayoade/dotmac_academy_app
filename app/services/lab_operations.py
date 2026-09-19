"""Durable lab-operation queue and worker ownership boundary.

Web callers only enqueue intents.  The lab worker claims one intent in a short
``FOR UPDATE SKIP LOCKED`` transaction, performs the external work, and settles
the row only while it still owns the claim.  A stale worker therefore cannot
publish database state after its lease has been reclaimed.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.services import lab_lifecycle
from app.services.exceptions import ConflictError
from app.services.host_lock import HostLockUnavailable
from app.services.labengine.interface import LabEngine, WrongLabHostError
from app.services.settings_store import effective

OPEN_STATES = ("queued", "claimed")
KINDS = ("deploy", "destroy", "check")
LEASE_SECONDS_BY_KIND = {"deploy": 1200, "destroy": 600, "check": 600}
MAX_ATTEMPTS_BY_KIND = {"deploy": 3, "destroy": 5, "check": 3}
RETRY_DELAY_SECONDS = 5
_CAPACITY_LOCK_KEY = 0x44414C  # "DAL"; one global Academy lab-capacity lock.
_BOOT_TOKEN = uuid4().hex[:8]
# Marks a `last_error` recorded for an operator-placement refusal (wrong lab
# host) rather than a genuine execution failure, so the automatic-destroy
# escalation count (a structural signal, not a message-substring guess about
# an engine's wording) can exclude these rows from the cumulative threshold.
_OPERATOR_REFUSAL_LAST_ERROR_PREFIX = "[operator-refusal] "
# Backward-compatibility fallback: a `WrongLabHostError`-caused failure that
# settled before `_OPERATOR_REFUSAL_LAST_ERROR_PREFIX` existed has no marker,
# just `str(exc)` verbatim. `ContainerlabEngine._require_lab_host` raises with
# this stable substring; matching it lets the escalation count exclude those
# legacy rows too, closing the gap between this fix and an earlier release.
_WRONG_LAB_HOST_LAST_ERROR_SUBSTRING = "containerlab operations require LAB_HOST_ROLE=lab"


def _now() -> datetime:
    return datetime.now(UTC)


def worker_identity() -> str:
    """Process-unique identity used to fence one running worker incarnation."""
    return f"{socket.gethostname()}:{os.getpid()}:{_BOOT_TOKEN}"


def _insert_open_operation_stmt(
    *, instance: LabInstance, kind: str, requested_by: UUID | None
) -> Any:
    """Build one insert-or-skip statement for the open-per-instance constraint.

    The explicit value list is security-sensitive: it is exactly the five
    columns granted to ``app_user`` by migration 0055.
    """
    return (
        insert(LabOperation)
        .values(
            id=uuid4(),
            tenant_id=instance.tenant_id,
            instance_id=instance.id,
            kind=kind,
            requested_by=requested_by,
        )
        .on_conflict_do_nothing(
            index_elements=[LabOperation.instance_id],
            index_where=LabOperation.state.in_(OPEN_STATES),
        )
        .returning(LabOperation.id)
    )


def _select_open_operation(db: Session, instance: LabInstance) -> LabOperation | None:
    """Return the current open (queued/claimed) operation for ``instance``, if any.

    Kept as its own call so a conflicting insert's re-check can observe the
    conflicting row settling out from under it between the insert and the
    re-select (see :func:`enqueue`).
    """
    return db.scalars(
        select(LabOperation)
        .where(LabOperation.instance_id == instance.id)
        .where(LabOperation.state.in_(OPEN_STATES))
    ).first()


def enqueue(
    db: Session,
    *,
    instance: LabInstance,
    kind: str,
    requested_by: UUID | None,
) -> LabOperation:
    """Insert one open intent per instance, returning the existing one on races.

    Under READ COMMITTED, the conflicting operation can settle (leave
    ``OPEN_STATES``) in the gap between our insert's conflict and the re-select
    that follows it. When that happens the re-select legitimately finds
    nothing — retry the whole insert once, since the conflict should now be
    gone. If the retried insert conflicts again and the re-select once more
    finds nothing (the new conflicting row also settled in that same narrow
    window), give up with a clean, callable-facing error rather than raising
    ``NoResultFound``.
    """
    if kind not in KINDS:
        raise ValueError(f"unsupported lab operation kind {kind!r}")
    inserted_id = db.scalar(
        _insert_open_operation_stmt(instance=instance, kind=kind, requested_by=requested_by)
    )
    if inserted_id is not None:
        return db.scalars(select(LabOperation).where(LabOperation.id == inserted_id)).one()
    existing = _select_open_operation(db, instance)
    if existing is not None:
        return existing
    # The conflicting row settled between our insert-conflict and the
    # re-select above. Retry the complete insert exactly once.
    retried_id = db.scalar(
        _insert_open_operation_stmt(instance=instance, kind=kind, requested_by=requested_by)
    )
    if retried_id is not None:
        return db.scalars(select(LabOperation).where(LabOperation.id == retried_id)).one()
    existing_after_retry = _select_open_operation(db, instance)
    if existing_after_retry is not None:
        return existing_after_retry
    raise ConflictError(
        f"could not enqueue {kind} operation for lab instance {instance.id}: "
        "a conflicting operation resolved during the enqueue retry"
    )


def claim_next(db: Session, *, claimed_by: str) -> LabOperation | None:
    """Claim the next ready operation; caller must commit immediately."""
    now = _now()
    op = db.scalars(
        select(LabOperation)
        .where(LabOperation.state == "queued")
        .where(LabOperation.not_before <= now)
        .order_by(
            case(
                (LabOperation.kind == "destroy", 0),
                (LabOperation.kind == "check", 1),
                else_=2,
            ),
            LabOperation.requested_at.asc(),
        )
        .with_for_update(skip_locked=True)
        .limit(1)
    ).first()
    if op is None:
        return None
    op.state = "claimed"
    op.claimed_by = claimed_by
    op.claimed_at = now
    op.heartbeat_at = now
    op.attempts += 1
    db.flush()
    return op


def heartbeat(db: Session, *, operation_id: UUID, claimed_by: str) -> bool:
    result = cast(CursorResult, db.execute(
        update(LabOperation)
        .where(LabOperation.id == operation_id)
        .where(LabOperation.state == "claimed")
        .where(LabOperation.claimed_by == claimed_by)
        .values(heartbeat_at=_now())
    ))
    return bool(result.rowcount)


def _refresh_claim(db: Session, *, operation_id: UUID, claimed_by: str) -> None:
    """Refresh a lease at a phase boundary in its own short transaction."""
    with Session(db.get_bind()) as heartbeat_db:
        alive = heartbeat(
            heartbeat_db,
            operation_id=operation_id,
            claimed_by=claimed_by,
        )
        heartbeat_db.commit()
    if not alive:
        raise RuntimeError("lab operation claim was lost before execution")


def _settle(
    db: Session,
    *,
    operation_id: UUID,
    claimed_by: str,
    state: str,
    error: str | None = None,
    refund_attempt: bool = False,
) -> bool:
    values: dict[str, object] = {
        "state": state,
        "heartbeat_at": _now(),
        "finished_at": _now(),
        "last_error": error,
    }
    if refund_attempt:
        values["attempts"] = func.greatest(LabOperation.attempts - 1, 0)
    result = cast(CursorResult, db.execute(
        update(LabOperation)
        .where(LabOperation.id == operation_id)
        .where(LabOperation.state == "claimed")
        .where(LabOperation.claimed_by == claimed_by)
        .values(**values)
    ))
    return bool(result.rowcount)


def _requeue_for_capacity(db: Session, op: LabOperation, instance: LabInstance) -> None:
    instance.status = "queued"
    op.state = "queued"
    op.claimed_by = None
    op.claimed_at = None
    op.heartbeat_at = None
    op.not_before = _now() + timedelta(seconds=RETRY_DELAY_SECONDS)
    op.last_error = None
    op.attempts = max(op.attempts - 1, 0)
    db.flush()


def _requeue_operation_after_host_lock(db: Session, op: LabOperation) -> None:
    """Return a claim's operation row to the queue after transient host-lock
    contention.

    Only touches the operation row. Callers decide separately whether the
    instance's status/error should be restored: for a "deploy" operation,
    ``_run_deploy`` may already have genuinely destroyed the old runtime
    before the lock contention was hit, so blindly restoring the pre-op
    instance state would be a false projection, not merely a conservative one.
    """
    op.state = "queued"
    op.claimed_by = None
    op.claimed_at = None
    op.heartbeat_at = None
    op.not_before = _now() + timedelta(seconds=RETRY_DELAY_SECONDS)
    op.last_error = None
    op.attempts = max(op.attempts - 1, 0)
    db.flush()


def _automatic_destroy_escalation_message(
    db: Session,
    *,
    instance_id: UUID,
    current_operation_id: UUID,
    current_operation_attempts: int,
) -> str | None:
    """Return an escalation message once cumulative automatic destroy
    ATTEMPTS for ``instance_id`` reach the destroy attempt ceiling, else
    ``None``.

    Sums ``attempts`` (not row count) across ``failed``, ``kind="destroy"``,
    ``requested_by IS NULL`` operations (automatic reaper-triggered destroys
    — user-initiated destroys pass a real person id) for this instance, plus
    the current failure's own ``attempts``. Summing attempts rather than
    counting rows matters because a single operation that hangs and burns its
    full attempt budget via lease-expiry (``reconcile_stuck`` reclaiming and
    re-attempting the same row) already represents up to
    ``MAX_ATTEMPTS_BY_KIND["destroy"]`` real attempts on its own — it must
    escalate at least as fast as that many separate single-attempt failures
    would, not need several more rows on top of it.

    Operator-placement refusals (``WrongLabHostError``, marked with
    ``_OPERATOR_REFUSAL_LAST_ERROR_PREFIX`` at settle time) are excluded: a
    misconfigured host role is not a genuine destroy execution failure. Rows
    settled before that marker existed (a stable substring of
    ``WrongLabHostError``'s own message, from
    ``ContainerlabEngine._require_lab_host``) are excluded the same way, so a
    gap between this fix landing and an earlier release of the worker leaves
    no unmarked wrong-host refusal able to count toward the threshold. Only
    failures after the instance's most recent *successful* ``deploy``
    operation count, so a successful manual redeploy starts a fresh window.
    The scan is bounded at the threshold rather than unbounded history: no
    single row can carry more attempts than the ceiling itself, so the most
    recent ``threshold`` failed rows are always enough to reach it if it can
    be reached at all.
    """
    threshold = MAX_ATTEMPTS_BY_KIND["destroy"]
    last_deploy_success_at = db.scalar(
        select(func.max(LabOperation.finished_at))
        .where(LabOperation.instance_id == instance_id)
        .where(LabOperation.kind == "deploy")
        .where(LabOperation.state == "succeeded")
    )
    prior_failure_query = (
        select(LabOperation.attempts)
        .where(LabOperation.instance_id == instance_id)
        .where(LabOperation.kind == "destroy")
        .where(LabOperation.state == "failed")
        .where(LabOperation.requested_by.is_(None))
        .where(LabOperation.id != current_operation_id)
        .where(
            or_(
                LabOperation.last_error.is_(None),
                ~LabOperation.last_error.startswith(
                    _OPERATOR_REFUSAL_LAST_ERROR_PREFIX
                ),
            )
        )
        .where(
            or_(
                LabOperation.last_error.is_(None),
                ~LabOperation.last_error.contains(
                    _WRONG_LAB_HOST_LAST_ERROR_SUBSTRING, autoescape=True
                ),
            )
        )
    )
    if last_deploy_success_at is not None:
        prior_failure_query = prior_failure_query.where(
            LabOperation.finished_at > last_deploy_success_at
        )
    bounded = (
        prior_failure_query.order_by(LabOperation.finished_at.desc())
        .limit(threshold)
        .subquery()
    )
    prior_attempts = int(db.scalar(select(func.sum(bounded.c.attempts))) or 0)
    cumulative_attempts = min(
        prior_attempts + current_operation_attempts, threshold
    )
    if cumulative_attempts < threshold:
        return None
    return (
        f"automatic destroy failed {cumulative_attempts} times; "
        "manual intervention required"
    )


def _capacity_available(db: Session, instance: LabInstance) -> bool:
    """Serialize admission and evaluate the effective, global capacity limit.

    Capacity is now keyed off ``runtime_presence`` ("present" or "unknown"),
    not lifecycle ``status`` — see ``app/models/lab.py`` — because ``status``
    cannot simultaneously carry lifecycle/UI meaning and physical runtime
    existence. ``already_consuming`` preserves its exact prior semantic ("is
    THIS instance already counted, so admit it regardless of the cap"): it
    was ``instance.status in ("active", "resetting")`` when presence didn't
    exist; it is now the presence-based equivalent of that same "already
    capacity-counted" condition.
    """
    db.execute(select(func.pg_advisory_xact_lock(_CAPACITY_LOCK_KEY)))
    cfg = effective(db)
    consuming = int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.runtime_presence.in_(("present", "unknown")))
        )
        or 0
    )
    already_consuming = instance.runtime_presence in ("present", "unknown")
    if already_consuming:
        return True
    tenant_consuming = int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.tenant_id == instance.tenant_id)
            .where(LabInstance.runtime_presence.in_(("present", "unknown")))
        )
        or 0
    )
    tenant_limit = cfg.max_concurrent_labs_per_tenant or cfg.max_concurrent_labs
    return (
        consuming < cfg.max_concurrent_labs
        and tenant_consuming < tenant_limit
    )


def _run_deploy(
    db: Session,
    instance: LabInstance,
    template: LabTemplate,
    engine: LabEngine,
    *,
    after_destroy: Callable[[], None] | None = None,
) -> None:
    """Idempotent destroy-then-deploy, preserving active state on destroy failure."""
    was_active = instance.status in ("active", "resetting")
    # The caller committed this reservation before engine work. Reasserting it
    # here is harmless and keeps the helper safe if called independently.
    instance.status = "resetting" if was_active else "provisioning"
    # Defensive restatement for standalone callers — the FIRST/authoritative
    # assignment of "unknown" for this deploy is made in run_claimed(), in the
    # same commit as the status reservation above, before this function ever
    # runs.
    instance.runtime_presence = "unknown"
    try:
        engine.destroy(instance.instance_name)
    except Exception as exc:
        # A failed destroy cannot prove the old runtime is absent. Count the
        # instance conservatively even for an initial/error retry so another
        # admission cannot consume the same capacity behind a leaked lab.
        instance.status = "active"
        instance.runtime_presence = "unknown"
        instance.error = str(exc)
        db.flush()
        raise
    if after_destroy is not None:
        after_destroy()
    lab_lifecycle.stop_consoles(instance)
    result = lab_lifecycle.provision(db, instance, engine, template)
    # ``provision`` may conservatively leave a failed deploy's status as
    # "active" (capacity-counted, unproven-absent runtime) rather than
    # "error" — its cleared-on-success ``error`` field is the authoritative
    # failure signal, not ``status`` alone.
    if result.status != "active" or result.error is not None:
        raise RuntimeError(result.error or "lab deployment failed")


def run_claimed(
    db: Session,
    *,
    operation_id: UUID,
    claimed_by: str,
    engine: LabEngine,
) -> str:
    """Execute and fenced-settle one claimed operation.

    Returns ``succeeded``, ``failed``, ``deferred``, or ``stale``.  The caller
    owns commit/rollback; a stale fence always rolls back database consequences.
    """
    op = db.get(LabOperation, operation_id)
    if op is None or op.state != "claimed" or op.claimed_by != claimed_by:
        db.rollback()
        return "stale"
    instance = db.get(LabInstance, op.instance_id)
    if instance is None:
        if not _settle(
            db,
            operation_id=operation_id,
            claimed_by=claimed_by,
            state="failed",
            error="lab instance no longer exists",
        ):
            db.rollback()
            return "stale"
        db.commit()
        return "failed"
    operation_kind = op.kind
    operation_instance_id = op.instance_id
    operation_requested_by = op.requested_by
    operation_attempts = op.attempts
    initial_instance_status = instance.status
    initial_instance_error = instance.error
    initial_instance_presence = instance.runtime_presence

    try:
        if operation_kind == "deploy":
            if not _capacity_available(db, instance):
                _requeue_for_capacity(db, op, instance)
                db.commit()
                return "deferred"
            # Make the reservation visible and release the advisory transaction
            # lock before slow external work. A crash now leaves a counted
            # transient state that reconcile_stuck() can repair and replay.
            instance.status = (
                "resetting" if instance.status in ("active", "resetting") else "provisioning"
            )
            # First/authoritative presence assignment for this deploy: this is
            # the durable reservation, committed before slow external work, so
            # a crash after this point must already treat the runtime as
            # uncertain rather than proven absent.
            instance.runtime_presence = "unknown"
            db.commit()
            refreshed_op = db.get(LabOperation, operation_id)
            refreshed_instance = (
                db.get(LabInstance, refreshed_op.instance_id)
                if refreshed_op is not None
                else None
            )
            if (
                refreshed_op is None
                or refreshed_instance is None
                or refreshed_op.state != "claimed"
                or refreshed_op.claimed_by != claimed_by
            ):
                db.rollback()
                return "stale"
            op = refreshed_op
            instance = refreshed_instance
            template = db.scalars(
                select(LabTemplate)
                .where(LabTemplate.tenant_id == instance.tenant_id)
                .where(LabTemplate.activity_id == instance.activity_id)
            ).one()
            _refresh_claim(db, operation_id=operation_id, claimed_by=claimed_by)
            _run_deploy(
                db,
                instance,
                template,
                engine,
                after_destroy=lambda: _refresh_claim(
                    db,
                    operation_id=operation_id,
                    claimed_by=claimed_by,
                ),
            )
        elif operation_kind == "destroy":
            _refresh_claim(db, operation_id=operation_id, claimed_by=claimed_by)
            lab_lifecycle.destroy(db, instance, engine)
        elif operation_kind == "check":
            template = db.scalars(
                select(LabTemplate)
                .where(LabTemplate.tenant_id == instance.tenant_id)
                .where(LabTemplate.activity_id == instance.activity_id)
            ).one()
            _refresh_claim(db, operation_id=operation_id, claimed_by=claimed_by)
            lab_lifecycle.grade(
                db,
                instance,
                engine,
                template,
                lab_lifecycle.handle_for(instance),
                before_each_check=lambda: _refresh_claim(
                    db,
                    operation_id=operation_id,
                    claimed_by=claimed_by,
                ),
            )
        else:  # Defensive against rows created outside the application.
            raise ValueError(f"unsupported lab operation kind {operation_kind!r}")
    except WrongLabHostError as exc:
        # Operator placement errors are not workload attempts and must not alter
        # learner-visible instance state. The engine increments the dedicated
        # refusal metric at the point it fails closed.
        db.rollback()
        unchanged_instance = db.get(LabInstance, operation_instance_id)
        if unchanged_instance is not None:
            unchanged_instance.status = initial_instance_status
            unchanged_instance.error = initial_instance_error
            # A host refusal proves no workload invocation occurred at all —
            # restore presence exactly as status/error are restored above.
            unchanged_instance.runtime_presence = initial_instance_presence
        if not _settle(
            db,
            operation_id=operation_id,
            claimed_by=claimed_by,
            state="failed",
            error=f"{_OPERATOR_REFUSAL_LAST_ERROR_PREFIX}{exc}",
            refund_attempt=True,
        ):
            db.rollback()
            return "stale"
        db.commit()
        return "failed"
    except HostLockUnavailable:
        # Another process holds the host containerlab lock. This is transient
        # host contention, not a workload failure or a fencing loss: refund
        # the attempt charged by claim_next and requeue the same row for a
        # prompt retry.
        db.rollback()
        unchanged_instance = db.get(LabInstance, operation_instance_id)
        refreshed_op = db.get(LabOperation, operation_id)
        if (
            unchanged_instance is None
            or refreshed_op is None
            or refreshed_op.state != "claimed"
            or refreshed_op.claimed_by != claimed_by
        ):
            db.rollback()
            return "stale"
        if operation_kind != "deploy":
            # Nothing destructive has necessarily happened yet for
            # destroy/check before this handler fires — safe to restore the
            # pre-execution instance state verbatim.
            unchanged_instance.status = initial_instance_status
            unchanged_instance.error = initial_instance_error
            unchanged_instance.runtime_presence = initial_instance_presence
        # For "deploy", _run_deploy already set instance.status to
        # "resetting"/"provisioning" for the whole destroy-then-provision
        # sequence before attempting the (possibly already-succeeded) destroy.
        # That value stays correctly capacity-counted (_capacity_available
        # treats provisioning/active/resetting alike) and, unlike the
        # pre-reset "active", does not falsely claim a working lab when the
        # real runtime may have just been torn down and not yet redeployed.
        # Leave it untouched. Presence is likewise left as "unknown" (already
        # set by _run_deploy/run_claimed's reservation) rather than restored:
        # a deploy may have already destroyed the old runtime before
        # contention hit during the subsequent provision call, so blindly
        # restoring the pre-op presence would be a false projection.
        _requeue_operation_after_host_lock(db, refreshed_op)
        db.commit()
        return "deferred"
    except Exception as exc:
        deploy_failure_status: str | None = None
        if operation_kind == "deploy":
            # Capture the intended failure projection before rollback. Active
            # includes resets and unproven destroys; every other origin is a
            # retryable error. Never commit partial DB consequences from the
            # failed execution merely to settle the operation.
            observed_status = instance.__dict__.get("status")
            deploy_failure_status = (
                "active" if observed_status in ("active", "resetting") else "error"
            )
        db.rollback()
        if deploy_failure_status is not None:
            failed_instance = db.get(LabInstance, operation_instance_id)
            if failed_instance is not None:
                failed_instance.status = deploy_failure_status
                failed_instance.error = str(exc)
                # A failed deploy cannot prove the runtime is absent, whatever
                # the (possibly conservative) status projection above says.
                failed_instance.runtime_presence = "unknown"
        elif operation_kind == "destroy":
            # A failed destroy (manual or automatic) cannot prove the runtime
            # is absent either — set this unconditionally, before the
            # automatic-only escalation check below, which never overrides
            # presence (see the destroy-escalation branch's comment).
            failed_instance = db.get(LabInstance, operation_instance_id)
            if failed_instance is not None:
                failed_instance.runtime_presence = "unknown"
            if operation_requested_by is None:
                # Automatic (reaper-triggered) destroys escalate after enough
                # cumulative failures instead of retrying forever;
                # user-initiated destroys (a real requested_by) are never
                # subject to this check.
                escalation_message = _automatic_destroy_escalation_message(
                    db,
                    instance_id=operation_instance_id,
                    current_operation_id=operation_id,
                    current_operation_attempts=operation_attempts,
                )
                if escalation_message is not None:
                    escalated_instance = db.get(LabInstance, operation_instance_id)
                    if escalated_instance is not None:
                        escalated_instance.status = "error"
                        escalated_instance.error = escalation_message
                        # Never force "absent" here — escalation must not
                        # falsely claim the runtime is gone. Presence stays
                        # "unknown", already set above.
        if not _settle(
            db,
            operation_id=operation_id,
            claimed_by=claimed_by,
            state="failed",
            error=str(exc),
        ):
            db.rollback()
            return "stale"
        db.commit()
        return "failed"

    if not _settle(
        db,
        operation_id=operation_id,
        claimed_by=claimed_by,
        state="succeeded",
    ):
        db.rollback()
        return "stale"
    db.commit()
    return "succeeded"


def reconcile_stuck(db: Session, *, lease_seconds: int | None = None) -> int:
    """Return expired claims and pre-cutover in-flight instances to the queue."""
    now = _now()
    claimed = db.scalars(
        select(LabOperation)
        .where(LabOperation.state == "claimed")
        .with_for_update(skip_locked=True)
    ).all()
    stuck = [
        op
        for op in claimed
        if (op.heartbeat_at or op.claimed_at or op.requested_at)
        < now
        - timedelta(
            seconds=(
                lease_seconds
                if lease_seconds is not None
                else LEASE_SECONDS_BY_KIND.get(op.kind, 600)
            )
        )
    ]
    for op in stuck:
        instance = db.get(LabInstance, op.instance_id)
        if op.attempts >= MAX_ATTEMPTS_BY_KIND.get(op.kind, 3):
            op.state = "failed"
            op.finished_at = now
            op.last_error = f"worker lease expired after {op.attempts} attempts"
            if instance is not None and op.kind in ("deploy", "destroy"):
                # An interrupted external mutation cannot prove runtime absence.
                instance.status = "active"
                instance.error = op.last_error
                instance.runtime_presence = "unknown"
            if (
                instance is not None
                and op.kind == "destroy"
                and op.requested_by is None
            ):
                # A stuck/lease-expired automatic destroy is the same
                # persistent-failure signal as a synchronous one — it must
                # count toward the same cumulative escalation threshold, or a
                # hanging engine lets the idle reaper re-enqueue destroys for
                # this instance forever.
                escalation_message = _automatic_destroy_escalation_message(
                    db,
                    instance_id=op.instance_id,
                    current_operation_id=op.id,
                    current_operation_attempts=op.attempts,
                )
                if escalation_message is not None:
                    instance.status = "error"
                    instance.error = escalation_message
                    # Presence stays "unknown" (set above) — never forced to
                    # "absent" by escalation.
            continue
        if instance is not None:
            if instance.status == "provisioning":
                instance.status = "queued"
            elif instance.status == "resetting":
                instance.status = "active"
            if op.kind in ("deploy", "destroy"):
                # The expired claim may have crossed the external mutation
                # boundary before the lease lapsed — set/retain "unknown" for
                # both requeue directions and for a destroy under the ceiling
                # (whose status stays "active" and hits neither branch above).
                instance.runtime_presence = "unknown"
        op.state = "queued"
        op.claimed_by = None
        op.claimed_at = None
        op.heartbeat_at = None
        op.not_before = now
        op.last_error = "worker lease expired; operation requeued"
    # Phase-1-to-worker cutover: old queued/provisioning LabInstance rows have
    # no operation because the former worker scanned the instance table. Repair
    # them idempotently so rollout needs no manual data migration.
    open_operation = (
        select(LabOperation.id)
        .where(LabOperation.instance_id == LabInstance.id)
        .where(LabOperation.state.in_(OPEN_STATES))
        .exists()
    )
    missing = db.scalars(
        select(LabInstance)
        .where(LabInstance.status.in_(("queued", "provisioning", "resetting")))
        .where(~open_operation)
        .with_for_update(skip_locked=True)
    ).all()
    for instance in missing:
        instance.status = "active" if instance.status == "resetting" else "queued"
        # Provenance is ambiguous for these old, pre-cutover rows — set
        # "unknown" before enqueueing rather than trusting whatever presence
        # value (if any) they already carry.
        instance.runtime_presence = "unknown"
        enqueue(db, instance=instance, kind="deploy", requested_by=None)
    db.flush()
    return len(stuck) + len(missing)
