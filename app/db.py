"""Database session.

`get_db` sets the `app.current_tenant` Postgres setting per request so RLS policies
can scope rows to the resolved tenant. `SET LOCAL` is transaction-scoped — the next
request from the connection pool starts with no setting and must set its own.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Request
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)
platform_engine = create_engine(
    settings.platform_database_url or settings.database_url,
    pool_pre_ping=True,
    pool_size=2,
    max_overflow=2,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
PlatformSessionLocal = sessionmaker(bind=platform_engine, autocommit=False, autoflush=False)


def set_tenant(db: Session, tenant_id, *, transaction_local: bool = True) -> None:
    """Apply the RLS tenant scope to `db`. The single writer of the setting.

    `transaction_local` is the whole subtlety, and getting it wrong is silent in
    both directions:

    * `True` (SET LOCAL) is **required** for `get_db`. Its session comes from a
      pool, so a scope that outlived the transaction would be inherited by the
      next request to borrow that connection — one tenant reading another's
      rows. Transaction-local means the setting dies with the transaction.

    * `False` is **required** for a long-running CLI session that commits more
      than once. A commit ends the transaction and takes `SET LOCAL` with it;
      `expire_on_commit` then reloads attributes on the *next* statement, which
      runs unscoped, and RLS fails closed — so a row the same session just
      wrote comes back invisible as `ObjectDeletedError`. That is not
      theoretical: it is what `load-banks` did on the first bank it committed.
      A CLI process owns its connections and exits with them, so a
      session-level setting cannot leak to anyone.
    """
    db.execute(
        text("SELECT set_config('app.current_tenant', :tenant_id, :is_local)"),
        {"tenant_id": str(tenant_id), "is_local": transaction_local},
    )


def get_db(request: Request) -> Generator[Session, None, None]:
    """Per-request DB session with tenant context applied for RLS.

    If `request.state.tenant` is None (platform-level routes), no tenant context is
    set — RLS policies will fail closed (zero rows) on any tenant-scoped table.
    Platform code uses a separate `get_platform_db` dependency with explicit grants,
    not the migration/admin role.
    """
    db = SessionLocal()
    try:
        tenant = getattr(request.state, "tenant", None)
        if tenant is not None:
            set_tenant(db, tenant.id)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_platform_db() -> Generator[Session, None, None]:
    """Online platform API DB session.

    Uses PLATFORM_DATABASE_URL (platform_api role) if set, else DATABASE_URL for local
    development. This role must not have BYPASSRLS; migrations and offline maintenance
    use MIGRATION_DATABASE_URL separately.
    """
    db = PlatformSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
