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
            db.execute(
                text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
                {"tenant_id": str(tenant.id)},
            )
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
