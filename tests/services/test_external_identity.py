"""Academy-local external identity and session-authority canaries.

These tests deliberately exercise Academy's own ``Person`` and ``AuthSession``
rows.  Importing the Starter identity models here would make the test certify a
cross-application database coupling instead of the product boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.auth import AuthSession
from app.models.external_identity import ExternalIdentityBinding
from app.models.person import Person
from app.services.exceptions import ConflictError
from app.services.external_identity import (
    bind_external_identity,
    disable_external_identity_binding,
    finalize_external_login,
)
from app.services.web_auth import _current_person, hash_token, start_session


def _person(db, tenant, *, status: str = "active") -> Person:
    person = Person(
        tenant_id=tenant.id,
        email=f"{uuid4().hex}@identity.test",
        first_name="External",
        last_name="Learner",
        status=status,
    )
    db.add(person)
    db.flush()
    return person


def _bind(db, tenant, person, *, subject: str = "CaseSensitiveSubject") -> ExternalIdentityBinding:
    return bind_external_identity(
        db,
        tenant_id=tenant.id,
        person_id=person.id,
        provider_binding=" customer-keycloak ",
        issuer=" https://idp.customer.test/realms/customer ",
        subject=f" {subject} ",
        bound_by="integrator:approved-command",
        reason="approved Academy component activation",
    )


def test_binding_trims_only_outer_whitespace_and_keeps_case(admin_session, tenant_a) -> None:
    person = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, person)

    assert binding.provider_binding == "customer-keycloak"
    assert binding.issuer == "https://idp.customer.test/realms/customer"
    assert binding.subject == "CaseSensitiveSubject"
    assert (
        admin_session.scalars(
            select(ExternalIdentityBinding).where(ExternalIdentityBinding.subject == "casesensitivesubject")
        ).first()
        is None
    )


def test_disabled_tuple_is_not_released_to_another_person(admin_session, tenant_a) -> None:
    first = _person(admin_session, tenant_a)
    second = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, first)
    disable_external_identity_binding(
        admin_session,
        tenant_id=tenant_a.id,
        binding_id=binding.id,
    )

    with pytest.raises(ConflictError):
        _bind(admin_session, tenant_a, second)

    restored = _bind(admin_session, tenant_a, first)
    assert restored.id == binding.id
    assert restored.is_active is True


def test_locked_finalizer_issues_a_provenance_stamped_session(admin_session, tenant_a) -> None:
    person = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, person)

    completed = finalize_external_login(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding=binding.provider_binding,
        issuer=binding.issuer,
        subject=binding.subject,
    )

    assert completed is not None
    session = admin_session.scalars(select(AuthSession).where(AuthSession.token_hash == completed.token_hash)).one()
    assert completed.person.id == person.id
    assert session.person_id == person.id
    assert session.external_identity_binding_id == binding.id
    assert binding.last_authenticated_at is not None


def test_disable_selectively_revokes_only_sessions_from_that_binding(admin_session, tenant_a) -> None:
    person = _person(admin_session, tenant_a)
    other = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, person)
    other_binding = _bind(admin_session, tenant_a, other, subject="OtherSubject")
    federated = finalize_external_login(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding=binding.provider_binding,
        issuer=binding.issuer,
        subject=binding.subject,
    )
    other_federated = finalize_external_login(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding=other_binding.provider_binding,
        issuer=other_binding.issuer,
        subject=other_binding.subject,
    )
    password_token = start_session(admin_session, tenant_a.id, person.id)
    assert federated is not None and other_federated is not None

    disable_external_identity_binding(
        admin_session,
        tenant_id=tenant_a.id,
        binding_id=binding.id,
    )

    sessions = {
        row.token_hash: row
        for row in admin_session.scalars(select(AuthSession).where(AuthSession.tenant_id == tenant_a.id))
    }
    assert sessions[federated.token_hash].revoked_at is not None
    assert sessions[other_federated.token_hash].revoked_at is None
    password = next(row for row in sessions.values() if row.external_identity_binding_id is None)
    assert password.token_hash != federated.token_hash
    assert password.revoked_at is None
    assert _current_person(admin_session, tenant_a.id, password_token) == person


def test_suspension_revokes_every_session_and_reenable_resurrects_none(admin_session, tenant_a) -> None:
    person = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, person)
    completed = finalize_external_login(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding=binding.provider_binding,
        issuer=binding.issuer,
        subject=binding.subject,
    )
    assert completed is not None

    from app.services.lifecycle import set_account_status

    set_account_status(
        admin_session,
        tenant_id=tenant_a.id,
        person_id=person.id,
        status="suspended",
    )
    assert _current_person(admin_session, tenant_a.id, completed.token) is None

    set_account_status(
        admin_session,
        tenant_id=tenant_a.id,
        person_id=person.id,
        status="active",
    )
    _bind(admin_session, tenant_a, person)
    assert _current_person(admin_session, tenant_a.id, completed.token) is None


def test_refresh_refuses_a_session_whose_binding_is_no_longer_active(admin_session, tenant_a) -> None:
    person = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, person)
    completed = finalize_external_login(
        admin_session,
        tenant_id=tenant_a.id,
        provider_binding=binding.provider_binding,
        issuer=binding.issuer,
        subject=binding.subject,
    )
    assert completed is not None

    # Simulates drift or a stale replica observation. The refresh path must
    # validate account, session AND binding rather than trust issuance history.
    binding.is_active = False
    admin_session.flush()
    assert _current_person(admin_session, tenant_a.id, completed.token) is None


def test_expired_external_session_is_refused(admin_session, tenant_a) -> None:
    person = _person(admin_session, tenant_a)
    binding = _bind(admin_session, tenant_a, person)
    token = "expired-external-token"
    session = AuthSession(
        tenant_id=tenant_a.id,
        person_id=person.id,
        token_hash=hash_token(token),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        external_identity_binding_id=binding.id,
    )
    admin_session.add(session)
    admin_session.flush()
    assert _current_person(admin_session, tenant_a.id, token) is None
