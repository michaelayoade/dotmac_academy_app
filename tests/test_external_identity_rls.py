"""PostgreSQL isolation and provenance canaries for Academy identity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.models.auth import AuthSession
from app.models.external_identity import ExternalIdentityBinding
from app.models.person import Person
from app.services.external_identity import bind_external_identity


def _person(db, tenant) -> Person:
    person = Person(
        tenant_id=tenant.id,
        email=f"{uuid4().hex}@rls.test",
        first_name="RLS",
        last_name="Canary",
    )
    db.add(person)
    db.flush()
    return person


def test_binding_rows_are_invisible_across_tenants(
    admin_session,
    app_user_session,
    tenant_a,
    tenant_b,
) -> None:
    person_a = _person(admin_session, tenant_a)
    person_b = _person(admin_session, tenant_b)
    for tenant, person, subject in (
        (tenant_a, person_a, "subject-a"),
        (tenant_b, person_b, "subject-b"),
    ):
        bind_external_identity(
            admin_session,
            tenant_id=tenant.id,
            person_id=person.id,
            provider_binding="primary",
            issuer="https://idp.test/realms/customer",
            subject=subject,
            bound_by="test",
            reason="RLS canary",
        )
    admin_session.commit()

    app_user_session.execute(
        text("SET LOCAL app.current_tenant = :tenant_id"),
        {"tenant_id": str(tenant_a.id)},
    )
    rows = app_user_session.scalars(select(ExternalIdentityBinding)).all()
    assert [(row.tenant_id, row.subject) for row in rows] == [(tenant_a.id, "subject-a")]


def test_session_cannot_cite_another_persons_binding(admin_session, tenant_a) -> None:
    person_a = _person(admin_session, tenant_a)
    person_b = _person(admin_session, tenant_a)
    binding = bind_external_identity(
        admin_session,
        tenant_id=tenant_a.id,
        person_id=person_a.id,
        provider_binding="primary",
        issuer="https://idp.test/realms/customer",
        subject="subject-a",
        bound_by="test",
        reason="provenance canary",
    )
    admin_session.add(
        AuthSession(
            tenant_id=tenant_a.id,
            person_id=person_b.id,
            token_hash="c" * 64,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            external_identity_binding_id=binding.id,
        )
    )
    with pytest.raises(IntegrityError):
        admin_session.flush()
