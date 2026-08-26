"""Composition canaries from a verified adapter receipt to Academy session."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.config import settings
from app.models.auth import AuthSession
from app.models.person import Person
from app.services import oidc_login
from app.services.external_identity import bind_external_identity
from app.services.oidc_state_store import PostgresStateStore


@dataclass(frozen=True, slots=True)
class _Started:
    url: str = "https://idp.example.test/authorize"
    state: str = "opaque-state"


@dataclass(frozen=True, slots=True)
class _Verified:
    issuer: str
    subject: str


class _RecordingClient:
    def __init__(self, *, issuer: str, subject: str) -> None:
        self.issuer = issuer
        self.subject = subject
        self.start_store: object | None = None
        self.complete_store: object | None = None

    def start_login(self, **kwargs):
        self.start_store = kwargs["state_store"]
        return _Started()

    def complete_login(self, **kwargs):
        self.complete_store = kwargs["state_store"]
        return _Verified(issuer=self.issuer, subject=self.subject)


def _person(db, tenant) -> Person:
    person = Person(
        tenant_id=tenant.id,
        email=f"{uuid4().hex}@oidc.test",
        first_name="OIDC",
        last_name="Learner",
        status="active",
    )
    db.add(person)
    db.flush()
    return person


@pytest.fixture(autouse=True)
def _provider_registration(monkeypatch):
    monkeypatch.setattr(settings, "oidc_provider_binding", "customer-keycloak")
    monkeypatch.setattr(
        settings,
        "oidc_issuer",
        "https://idp.example.test/realms/customer",
    )


def test_protocol_client_is_given_the_request_bound_postgres_store(
    admin_session,
    tenant_a,
    monkeypatch,
) -> None:
    client = _RecordingClient(issuer=settings.oidc_issuer, subject="subject-1")
    monkeypatch.setattr(oidc_login, "_CLIENT", client)

    started = oidc_login.begin_login(admin_session, tenant_id=tenant_a.id)

    assert started.url == "https://idp.example.test/authorize"
    assert isinstance(client.start_store, PostgresStateStore)


def test_verified_receipt_finalizes_through_the_local_locked_owner(
    admin_session,
    tenant_a,
    monkeypatch,
) -> None:
    person = _person(admin_session, tenant_a)
    binding = bind_external_identity(
        admin_session,
        tenant_id=tenant_a.id,
        person_id=person.id,
        provider_binding=settings.oidc_provider_binding,
        issuer=settings.oidc_issuer,
        subject="CaseSensitiveSubject",
        bound_by="integrator:approved-operation",
        reason="managed Academy activation",
    )
    client = _RecordingClient(
        issuer=settings.oidc_issuer,
        subject="CaseSensitiveSubject",
    )
    monkeypatch.setattr(oidc_login, "_CLIENT", client)

    completed = oidc_login.complete_login(
        admin_session,
        tenant_id=tenant_a.id,
        code="authorization-code",
        state="opaque-state",
        stored_state="opaque-state",
    )

    session = admin_session.scalars(select(AuthSession).where(AuthSession.token_hash == completed.token_hash)).one()
    assert completed.person.id == person.id
    assert session.external_identity_binding_id == binding.id
    assert isinstance(client.complete_store, PostgresStateStore)


def test_verified_unbound_subject_has_no_jit_or_email_fallback(
    admin_session,
    tenant_a,
    monkeypatch,
) -> None:
    before = admin_session.scalars(select(Person)).all()
    client = _RecordingClient(
        issuer=settings.oidc_issuer,
        subject="unbound-subject",
    )
    monkeypatch.setattr(oidc_login, "_CLIENT", client)

    with pytest.raises(oidc_login.LoginRefused):
        oidc_login.complete_login(
            admin_session,
            tenant_id=tenant_a.id,
            code="authorization-code",
            state="opaque-state",
            stored_state="opaque-state",
        )

    assert admin_session.scalars(select(Person)).all() == before
    assert admin_session.scalars(select(AuthSession)).all() == []
