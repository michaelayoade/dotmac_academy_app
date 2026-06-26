"""Test fixtures.

Two-tenant setup: every isolation test gets `tenant_a` and `tenant_b` and a
`client_for(tenant)` helper that issues requests against the right subdomain.

These tests REQUIRE a real Postgres with RLS — SQLite has no RLS. CI/dev should
spin up a disposable Postgres (testcontainers, docker compose, or a per-test schema).

This skeleton uses `os.getenv("TEST_DATABASE_URL")` — set it before running tests.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture(scope="session")
def admin_engine():
    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — these tests require a real Postgres")
    engine = create_engine(url, future=True)
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def _set_database_url(monkeypatch):
    """Pin DATABASE_URL for the app under test to the TEST_DATABASE_URL."""
    url = os.getenv("TEST_DATABASE_URL")
    if url:
        monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("PLATFORM_ROOT_DOMAIN", "localhost")


@pytest.fixture
def admin_session(admin_engine) -> Generator[Session, None, None]:
    """Connection as app_admin — RLS bypassed. Used by fixtures to set up data."""
    SessionLocal = sessionmaker(bind=admin_engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    try:
        yield db
        db.rollback()  # keep test DB clean — explicit commits required where needed
    finally:
        db.close()


@pytest.fixture
def tenant_a(admin_session: Session):
    from app.models.tenant import Tenant
    t = Tenant(slug="alpha", name="Alpha Test Tenant")
    admin_session.add(t)
    admin_session.commit()
    admin_session.refresh(t)
    yield t
    admin_session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(t.id)})
    admin_session.commit()


@pytest.fixture
def tenant_b(admin_session: Session):
    from app.models.tenant import Tenant
    t = Tenant(slug="beta", name="Beta Test Tenant")
    admin_session.add(t)
    admin_session.commit()
    admin_session.refresh(t)
    yield t
    admin_session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(t.id)})
    admin_session.commit()


@pytest.fixture
def app_client():
    """TestClient that lets you set Host header per request."""
    from app.main import app
    return TestClient(app)


def client_for(client: TestClient, tenant_slug: str) -> TestClient:
    """Wrap a TestClient so every request carries Host: {slug}.localhost."""
    client.headers.update({"Host": f"{tenant_slug}.localhost"})
    return client
