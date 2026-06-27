"""Cross-tenant lab orchestration jobs (Task 7): provisioning worker + reaper.

Unlike the per-request lifecycle helpers in :mod:`app.services.lab_lifecycle`
(which take ``db`` and only ``flush`` — the request handler owns the
transaction), these are background jobs that run across ALL tenants. They MUST
use an ``app_admin`` (``BYPASSRLS``) session — the only role that can see every
tenant's rows — and they OWN their transaction boundary, so they ``commit``.

Use :func:`admin_session` to obtain such a session (bound to
``settings.migration_database_url``). The two entry points are:

* :func:`drain_once` — deploy the oldest pending instances up to the global
  ``MAX_CONCURRENT_LABS`` cap (the ``lab-worker`` loop calls this).
* :func:`reap_idle` — destroy active instances idle past ``LAB_IDLE_MINUTES``
  (the ``reap-labs`` timer calls this).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.models.lab import LabInstance, LabTemplate
from app.services.lab_lifecycle import destroy, provision
from app.services.labengine.interface import LabEngine


@contextmanager
def admin_session() -> Iterator[Session]:
    """Yield an ``app_admin`` (BYPASSRLS) Session bound to MIGRATION_DATABASE_URL.

    Cross-tenant jobs need a role that sees every tenant's rows; the per-request
    ``app_user`` session is RLS-scoped to one tenant. The engine is created and
    disposed per call (these are short-lived batch invocations / a slow loop).
    """
    engine = create_engine(settings.migration_database_url, future=True)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _global_active_count(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.status == "active")
        )
        or 0
    )


def drain_once(db: Session, engine: LabEngine) -> int:
    """Deploy oldest pending (queued|provisioning) instances up to the cap.

    Iterates pending instances oldest-first. For each, while the global active
    capacity remains (``count(active) < MAX_CONCURRENT_LABS``), looks up the
    instance's :class:`LabTemplate` and calls
    :func:`app.services.lab_lifecycle.provision`, committing per instance. A row
    that errors during provision stays as ``error`` for visibility/retry — only
    rows that reach ``active`` count as provisioned. Returns the count newly
    moved to ``active``.
    """
    pending = db.scalars(
        select(LabInstance)
        .where(LabInstance.status.in_(("queued", "provisioning")))
        .order_by(LabInstance.created_at.asc())
    ).all()

    provisioned = 0
    for inst in pending:
        if _global_active_count(db) >= settings.max_concurrent_labs:
            break
        template = db.scalars(
            select(LabTemplate).where(LabTemplate.activity_id == inst.activity_id)
        ).first()
        if template is None:
            continue
        provision(db, inst, engine, template)
        db.commit()
        if inst.status == "active":
            provisioned += 1
    return provisioned


def reap_idle(db: Session, engine: LabEngine) -> int:
    """Destroy active instances idle past ``LAB_IDLE_MINUTES``; mark them reaped.

    Selects ``active`` instances whose ``last_active_at`` is older than the idle
    cutoff and calls :func:`app.services.lab_lifecycle.destroy` (which marks the
    row ``reaped``), committing per instance. Returns the number reaped.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=settings.lab_idle_minutes)
    idle = db.scalars(
        select(LabInstance)
        .where(LabInstance.status == "active")
        .where(LabInstance.last_active_at < cutoff)
    ).all()

    reaped = 0
    for inst in idle:
        destroy(db, inst, engine)
        db.commit()
        reaped += 1
    return reaped
