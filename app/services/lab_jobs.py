"""Cross-tenant lab operation worker and enqueue-only idle reaper.

Unlike the per-request lifecycle helpers in :mod:`app.services.lab_lifecycle`
(which take ``db`` and only ``flush`` — the request handler owns the
transaction), these are background jobs that run across ALL tenants. They need
an offline/BYPASSRLS session that can see every tenant's rows and they OWN their
transaction boundary, so they ``commit``. Containerlab execution is narrower:
it requires the exact dedicated ``app_admin`` worker identity.

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
    """Yield a dedicated, live-verified ``app_admin`` lab-worker Session."""
    worker_url = settings.lab_worker_database_url
    try:
        worker_role = make_url(worker_url).username
    except Exception as exc:
        raise RuntimeError("LAB_WORKER_DATABASE_URL is invalid") from exc
    if worker_role != "app_admin":
        raise RuntimeError("LAB_WORKER_DATABASE_URL must authenticate as app_admin")
    engine = create_engine(worker_url, future=True)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = factory()
    try:
        if db.scalar(text("SELECT current_user")) != "app_admin":
            raise RuntimeError("lab worker database session is not app_admin")
        # ``lab_operations`` has FORCE ROW LEVEL SECURITY with a tenant_id GUC
        # policy (see 0055_lab_operations.py). Being the app_admin role is not
        # enough on its own — if BYPASSRLS were ever missing or revoked from
        # an already-existing role, the worker would silently see an empty
        # queue (RLS resolves against a NULL tenant GUC) and stop processing
        # with no error at all. Check the actual role attribute, not just the
        # role name, so that failure mode raises instead of going quiet.
        if not db.scalar(
            text("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'app_admin'")
        ):
            raise RuntimeError("app_admin role does not have BYPASSRLS")
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
    ``app_admin`` session :func:`admin_session` yields — a tenant-scoped session
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
    """
    runtime = engine.inventory()
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
    queued = 0
    destroyed = 0

    for name in sorted(runtime):
        if not name.startswith("dal-"):
            continue
        instance = by_name.get(name)
        if instance is None:
            engine.destroy(name)
            destroyed += 1
            continue
        if (
            instance.status not in ("provisioning", "active", "resetting")
            and instance.id not in open_instance_ids
        ):
            instance.status = "active"
            instance.error = "runtime existed for a non-live database row; destroy enqueued"
            lab_operations.enqueue(db, instance=instance, kind="destroy", requested_by=None)
            open_instance_ids.add(instance.id)
            queued += 1

    for instance in rows:
        if (
            instance.status in ("provisioning", "active", "resetting")
            and instance.instance_name not in runtime
            and instance.id not in open_instance_ids
        ):
            if instance.error is not None:
                # A prior failure was conservatively capacity-counted because
                # runtime absence was unknown. Inventory has now proved absence,
                # so expose a retryable error without starting a fresh automatic
                # attempt loop or retaining a phantom capacity reservation.
                instance.status = "error"
                instance.error = f"{instance.error}; containerlab runtime is absent"
            else:
                instance.error = "database row was live but no containerlab runtime was found"
                lab_operations.enqueue(
                    db, instance=instance, kind="deploy", requested_by=None
                )
                open_instance_ids.add(instance.id)
                queued += 1

    db.flush()
    return queued, destroyed
