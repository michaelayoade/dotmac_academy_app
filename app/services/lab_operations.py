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
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import case, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.services import lab_lifecycle
from app.services.labengine.interface import LabEngine, WrongLabHostError
from app.services.settings_store import effective

OPEN_STATES = ("queued", "claimed")
KINDS = ("deploy", "destroy", "check")
LEASE_SECONDS_BY_KIND = {"deploy": 1200, "destroy": 600, "check": 600}
MAX_ATTEMPTS_BY_KIND = {"deploy": 3, "destroy": 5, "check": 3}
RETRY_DELAY_SECONDS = 5
_CAPACITY_LOCK_KEY = 0x44414C  # "DAL"; one global Academy lab-capacity lock.
_BOOT_TOKEN = uuid4().hex[:8]


def _now() -> datetime:
    return datetime.now(UTC)


def worker_identity() -> str:
    """Process-unique identity used to fence one running worker incarnation."""
    return f"{socket.gethostname()}:{os.getpid()}:{_BOOT_TOKEN}"


def enqueue(
    db: Session,
    *,
    instance: LabInstance,
    kind: str,
    requested_by: UUID | None,
) -> LabOperation:
    """Insert one open intent per instance, returning the existing one on races.

    The explicit value list is security-sensitive: it is exactly the five
    columns granted to ``app_user`` by migration 0055.
    """
    if kind not in KINDS:
        raise ValueError(f"unsupported lab operation kind {kind!r}")
    op_id = uuid4()
    stmt = (
        insert(LabOperation)
        .values(
            id=op_id,
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
    inserted_id = db.scalar(stmt)
    if inserted_id is not None:
        return db.scalars(select(LabOperation).where(LabOperation.id == inserted_id)).one()
    return db.scalars(
        select(LabOperation)
        .where(LabOperation.instance_id == instance.id)
        .where(LabOperation.state.in_(OPEN_STATES))
    ).one()


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


def _capacity_available(db: Session, instance: LabInstance) -> bool:
    """Serialize admission and evaluate the effective, global capacity limit."""
    db.execute(select(func.pg_advisory_xact_lock(_CAPACITY_LOCK_KEY)))
    cfg = effective(db)
    consuming = int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.status.in_(("provisioning", "active", "resetting")))
        )
        or 0
    )
    already_consuming = instance.status in ("active", "resetting")
    if already_consuming:
        return True
    tenant_consuming = int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.tenant_id == instance.tenant_id)
            .where(LabInstance.status.in_(("provisioning", "active", "resetting")))
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
    try:
        engine.destroy(instance.instance_name)
    except Exception as exc:
        # A failed destroy cannot prove the old runtime is absent. Count the
        # instance conservatively even for an initial/error retry so another
        # admission cannot consume the same capacity behind a leaked lab.
        instance.status = "active"
        instance.error = str(exc)
        db.flush()
        raise
    if after_destroy is not None:
        after_destroy()
    lab_lifecycle.stop_consoles(instance)
    result = lab_lifecycle.provision(db, instance, engine, template)
    if result.status != "active":
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
    initial_instance_status = instance.status
    initial_instance_error = instance.error

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
        if not _settle(
            db,
            operation_id=operation_id,
            claimed_by=claimed_by,
            state="failed",
            error=str(exc),
            refund_attempt=True,
        ):
            db.rollback()
            return "stale"
        db.commit()
        return "failed"
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
            continue
        if instance is not None:
            if instance.status == "provisioning":
                instance.status = "queued"
            elif instance.status == "resetting":
                instance.status = "active"
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
        enqueue(db, instance=instance, kind="deploy", requested_by=None)
    db.flush()
    return len(stuck) + len(missing)
