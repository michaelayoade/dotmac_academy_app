"""Cross-tenant lab operation worker and enqueue-only idle reaper.

Unlike the per-request lifecycle helpers in :mod:`app.services.lab_lifecycle`
(which take ``db`` and only ``flush`` — the request handler owns the
transaction), these are background jobs that run across ALL tenants. They need
an offline/BYPASSRLS session that can see every tenant's rows and they OWN their
transaction boundary, so they ``commit``. Containerlab execution is narrower:
it requires the exact dedicated ``academy_lab_worker`` identity.

Use :func:`lab_worker_session` for containerlab worker/reconciler execution.
The pre-existing :func:`admin_session` remains the generic offline session used
by unrelated scheduled jobs and metrics; keeping the two credentials separate
prevents the web host from needing the lab worker DSN.

* :func:`drain_once` — claim and execute durable ``lab_operations`` rows.
* :func:`request_idle_reaps` — enqueue destroy intents without touching the
  engine (the web-host timer calls this).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

import app.models  # noqa: F401  # ensure all FK target tables are registered for CLI workers
from app.config import settings
from app.models.lab import LabInstance, LabOperation
from app.services import lab_operations
from app.services.lab_lifecycle import console_pids, kill_consoles
from app.services.labengine.interface import LabEngine


@contextmanager
def admin_session() -> Iterator[Session]:
    """Yield the repository's generic cross-tenant offline Session.

    This preserves the established session used by metrics and non-lab timers.
    Containerlab ownership paths must use :func:`lab_worker_session` instead.
    """
    engine = create_engine(settings.migration_database_url, future=True)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@contextmanager
def lab_worker_session() -> Iterator[Session]:
    """Yield a dedicated, live-verified ``academy_lab_worker`` Session."""
    worker_url = settings.lab_worker_database_url
    try:
        worker_role = make_url(worker_url).username
    except Exception as exc:
        raise RuntimeError("LAB_WORKER_DATABASE_URL is invalid") from exc
    if worker_role != "academy_lab_worker":
        raise RuntimeError("LAB_WORKER_DATABASE_URL must authenticate as academy_lab_worker")
    engine = create_engine(worker_url, future=True)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = factory()
    try:
        if db.scalar(text("SELECT current_user")) != "academy_lab_worker":
            raise RuntimeError("lab worker database session is not academy_lab_worker")
        # ``lab_operations`` has FORCE ROW LEVEL SECURITY with a tenant_id GUC
        # policy (see 0055_lab_operations.py). Being the worker role is not
        # enough on its own — if BYPASSRLS were ever missing or revoked from
        # an already-existing role, the worker would silently see an empty
        # queue (RLS resolves against a NULL tenant GUC) and stop processing
        # with no error at all. Check the actual role attribute, not just the
        # role name, so that failure mode raises instead of going quiet.
        if not db.scalar(
            text("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'academy_lab_worker'")
        ):
            raise RuntimeError("academy_lab_worker role does not have BYPASSRLS")
        safe_posture = db.scalar(
            text(
                """SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
                    AND NOT rolreplication AND NOT rolinherit
                    AND NOT EXISTS (
                        SELECT 1 FROM pg_auth_members m
                        WHERE m.member = r.oid OR m.roleid = r.oid
                    )
                FROM pg_roles r
                WHERE r.rolname = 'academy_lab_worker'"""
            )
        )
        if not safe_posture:
            raise RuntimeError(
                "academy_lab_worker role has unsafe attributes or role memberships"
            )
        owns = db.scalar(
            text(
                """SELECT EXISTS (
                    SELECT 1 FROM pg_database
                    WHERE datname = current_database()
                      AND pg_get_userbyid(datdba) = 'academy_lab_worker'
                ) OR EXISTS (
                    SELECT 1 FROM pg_namespace
                    WHERE pg_get_userbyid(nspowner) = 'academy_lab_worker'
                      AND nspname NOT IN ('pg_catalog', 'information_schema')
                      AND nspname NOT LIKE 'pg_toast%'
                ) OR EXISTS (
                    SELECT 1
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE pg_get_userbyid(c.relowner) = 'academy_lab_worker'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND n.nspname NOT LIKE 'pg_toast%'
                      AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                )"""
            )
        )
        if owns:
            raise RuntimeError("academy_lab_worker must not own the database, schema, or application relations")
        yield db
    finally:
        db.close()
        engine.dispose()


def drain_once(db: Session, engine: LabEngine, *, claimed_by: str | None = None) -> int:
    """Claim and execute ready operations until the queue has no ready row.

    Each claim is committed before external work starts, keeping
    ``FOR UPDATE SKIP LOCKED`` inside a short transaction. Settlement is fenced
    by the worker identity in :func:`lab_operations.run_claimed`.
    """
    worker = claimed_by or lab_operations.worker_identity()
    completed = 0
    while True:
        op = lab_operations.claim_next(db, claimed_by=worker)
        if op is None:
            db.rollback()
            break
        operation_id = op.id
        db.commit()
        outcome = lab_operations.run_claimed(
            db,
            operation_id=operation_id,
            claimed_by=worker,
            engine=engine,
        )
        if outcome == "succeeded":
            completed += 1
    return completed


def request_idle_reaps(db: Session) -> int:
    """Enqueue destroy intents for idle instances; never call the lab engine."""
    from app.services.settings_store import effective

    cutoff = datetime.now(UTC) - timedelta(minutes=effective(db).lab_idle_minutes)
    idle = db.scalars(
        select(LabInstance)
        .where(LabInstance.status == "active")
        .where(LabInstance.last_active_at < cutoff)
    ).all()

    requested = 0
    for inst in idle:
        op = lab_operations.enqueue(db, instance=inst, kind="destroy", requested_by=None)
        if op.kind == "destroy":
            requested += 1
    db.commit()
    return requested


def sweep_orphan_consoles(db: Session) -> int:
    """Kill ttyd consoles whose instance is no longer live; return the count.

    Per-instance teardown is best effort — the process outlives its instance
    whenever ``destroy`` is skipped, the row is deleted, or the killing process
    lacks permission. Nothing then reaps it, so consoles accumulate: this sweep is
    the backstop that makes the leak self-correcting rather than permanent.

    A console is an orphan when its instance id (parsed from the ttyd ``-b`` base
    path) has no ``provisioning``/``resetting``/``active`` row. Cross-tenant, so it needs the
    offline session :func:`admin_session` yields — a tenant-scoped session
    would see another tenant's live console as an orphan and kill it.
    """
    running = console_pids()
    if not running:
        return 0
    live = {
        str(row)
        for row in db.scalars(
            select(LabInstance.id).where(
                LabInstance.status.in_(("provisioning", "active", "resetting"))
            )
        ).all()
    }
    return kill_consoles(
        pid
        for instance_id, pids in running.items()
        if instance_id not in live
        for pid in pids
    )


def reconcile_runtime(db: Session, engine: LabEngine) -> tuple[int, int]:
    """Cross-check containerlab inventory against rows and repair drift.

    Returns ``(queued_repairs, destroyed_rowless_orphans)``. Only Academy's
    ``dal-`` namespace is eligible for direct cleanup; unrelated containerlab
    runtimes on the same host are never touched.

    Structured in four phases so that host-lock contention (raised as
    :class:`~app.services.host_lock.HostLockUnavailable`, propagated to the
    caller) can never leave a half-applied repair plan behind:

    1. Locked inventory (``engine.inventory()`` — the lock is acquired and
       released inside the engine call itself).
    2. Database reads and repair-plan calculation. No row locks and no host
       lock are held here — this is pure computation over already-fetched
       data.
    3. Locked rowless-orphan destroys (``engine.destroy()`` per orphan, each
       independently acquiring/releasing the host lock). No database row is
       mutated in this phase, so if the host lock is contended partway
       through this loop, there is nothing to unwind.
    4. Database projections/enqueues, only after every host operation this
       pass needed has already completed. This phase cannot raise
       ``HostLockUnavailable`` — it never touches the engine. Phase 3's
       destroys each carry their own multi-minute timeout, so real time
       passes between Phase 2's snapshot and Phase 4's mutations — long
       enough for an unrelated, concurrent operation (e.g. a user-initiated
       reset running via the normal worker path) to change an instance's
       true state in the meantime. Phase 4 therefore re-validates each
       candidate's CURRENT status and CURRENT open-operation membership
       immediately before mutating it, rather than trusting the Phase 2
       snapshot for anything beyond "this instance was structurally
       interesting enough to look at again" — otherwise a freshly-succeeded
       redeploy could be paved over with a destroy enqueued against stale
       data.

    If ``engine.inventory()`` or a ``engine.destroy()`` call raises
    ``HostLockUnavailable``, this function does not catch it: it propagates
    to :func:`app.cli._lab_reconcile`, which rolls back this pass's
    (nonexistent, by construction — phases 1-3 make no database writes) and
    exits cleanly rather than raising, so the reconciler simply retries on
    its own 1-minute timer.
    """
    # Phase 1 — locked inventory.
    runtime = engine.inventory()

    # Phase 2 — database reads and repair-plan calculation; no locks held.
    rows = db.scalars(select(LabInstance)).all()
    if len({row.instance_name for row in rows}) != len(rows):
        raise RuntimeError("duplicate lab instance names prevent safe runtime reconciliation")
    by_name = {row.instance_name: row for row in rows}
    open_instance_ids = set(
        db.scalars(
            select(LabOperation.instance_id).where(
                LabOperation.state.in_(lab_operations.OPEN_STATES)
            )
        ).all()
    )

    rowless_orphans = [
        name for name in sorted(runtime) if name.startswith("dal-") and name not in by_name
    ]
    db_only_repairs = [
        instance
        for name in sorted(runtime)
        if name.startswith("dal-") and (instance := by_name.get(name)) is not None
        and instance.status not in ("provisioning", "active", "resetting")
        and instance.id not in open_instance_ids
    ]
    missing_runtime = [
        instance
        for instance in rows
        if instance.status in ("provisioning", "active", "resetting")
        and instance.instance_name not in runtime
        and instance.id not in open_instance_ids
    ]

    # Phase 3 — locked rowless-orphan destroys. No database row is mutated
    # above or here, so a HostLockUnavailable raised mid-loop leaves nothing
    # for the caller to roll back.
    destroyed = 0
    for name in rowless_orphans:
        engine.destroy(name)
        destroyed += 1

    # Phase 4 — database projections/enqueues, after all required host
    # operations for this pass have completed. Re-fetch open-operation
    # membership fresh here rather than reusing Phase 2's — Phase 3's
    # destroys can each take minutes, plenty of time for a concurrent,
    # unrelated operation to appear against one of these instances.
    fresh_open_instance_ids = set(
        db.scalars(
            select(LabOperation.instance_id).where(
                LabOperation.state.in_(lab_operations.OPEN_STATES)
            )
        ).all()
    )

    queued = 0
    for instance in db_only_repairs:
        # Re-check this exact instance's current state immediately before
        # mutating it — Phase 2 only proved it looked eligible at snapshot
        # time. If a concurrent operation now has it live or already claimed,
        # something else is handling it and this pass must not interfere.
        db.refresh(instance)
        if (
            instance.status in ("provisioning", "active", "resetting")
            or instance.id in fresh_open_instance_ids
        ):
            continue
        instance.status = "active"
        instance.error = "runtime existed for a non-live database row; destroy enqueued"
        lab_operations.enqueue(db, instance=instance, kind="destroy", requested_by=None)
        queued += 1

    for instance in missing_runtime:
        # Same re-validation, mirrored: a concurrent redeploy since Phase 2
        # would have left the instance live again and/or claimed by an open
        # operation, and must not be paved over with a stale destroy/deploy.
        db.refresh(instance)
        if (
            instance.status not in ("provisioning", "active", "resetting")
            or instance.id in fresh_open_instance_ids
        ):
            continue
        if instance.error is not None:
            # A prior failure was conservatively capacity-counted because
            # runtime absence was unknown. Inventory has now proved absence,
            # so expose a retryable error without starting a fresh automatic
            # attempt loop or retaining a phantom capacity reservation.
            instance.status = "error"
            instance.error = f"{instance.error}; containerlab runtime is absent"
        else:
            instance.error = "database row was live but no containerlab runtime was found"
            lab_operations.enqueue(db, instance=instance, kind="deploy", requested_by=None)
            queued += 1

    db.flush()
    return queued, destroyed
