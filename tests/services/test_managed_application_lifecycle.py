"""Product-owner canaries for Academy managed application lifecycle."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app.models.auth import AuthSession
from app.models.managed_application_lifecycle import ManagedApplicationLifecycleOperation
from app.models.person import Person
from app.services.managed_application_lifecycle import (
    ApplicationLifecycleError,
    ApplicationLifecycleTarget,
    ExternalSubjectTarget,
    apply,
    cancel,
    observe,
    plan,
)


@pytest.fixture(autouse=True)
def _installed_provider(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "oidc_provider_binding", "customer-keycloak")
    monkeypatch.setattr(
        settings,
        "oidc_issuer",
        "https://idp.customer.example/realms/customer",
    )


def _person(db, tenant, *, status: str = "active") -> Person:
    person = Person(
        tenant_id=tenant.id,
        email=f"{uuid4().hex}@lifecycle.test",
        first_name="Managed",
        last_name="Learner",
        status=status,
    )
    db.add(person)
    db.flush()
    return person


def _target(tenant, person, *, state: str = "suspended", subject: str = "CaseSensitiveSubject"):
    return ApplicationLifecycleTarget(
        tenant_id=tenant.id,
        person_id=person.id,
        desired_state=state,
        external_subject=ExternalSubjectTarget(
            provider_binding="customer-keycloak",
            issuer="https://idp.customer.example/realms/customer",
            subject=subject,
        ),
    )


def _apply_plan(db, tenant, target, *, key: str = "command-1"):
    saved = plan(db, tenant_id=tenant.id, idempotency_key=key, target=target)
    return apply(
        db,
        tenant_id=tenant.id,
        operation_ref=saved.operation_ref,
        idempotency_key=key,
        target=target,
        target_digest=saved.target_digest,
        expected_state_digest=saved.expected_state_digest,
        plan_digest=saved.plan_digest,
    )


def test_plan_is_exact_and_same_key_same_target_replays(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    target = _target(tenant_a, person)

    first = plan(admin_session, tenant_id=tenant_a.id, idempotency_key=" command-1 ", target=target)
    replay = plan(admin_session, tenant_id=tenant_a.id, idempotency_key="command-1", target=target)

    assert replay == first
    assert first.actions == (
        "external-identity.bind-or-enable",
        "external-identity.disable",
        "account.suspend",
    )
    assert first.target["external_subject"] == {
        "provider_binding": "customer-keycloak",
        "issuer": "https://idp.customer.example/realms/customer",
        "subject": "CaseSensitiveSubject",
    }
    assert first.target_digest.startswith("sha256:")
    assert first.expected_state_digest.startswith("sha256:")
    assert first.plan_digest.startswith("sha256:")


def test_same_key_different_exact_subject_is_a_conflict(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    plan(admin_session, tenant_id=tenant_a.id, idempotency_key="command-1", target=_target(tenant_a, person))

    with pytest.raises(ApplicationLifecycleError) as refusal:
        plan(
            admin_session,
            tenant_id=tenant_a.id,
            idempotency_key="command-1",
            target=_target(tenant_a, person, subject="casesensitivesubject"),
        )
    assert refusal.value.code == "idempotency_conflict"


def test_concurrent_same_plan_has_one_operation(admin_engine, admin_session, tenant_a):
    """The unique key arbitrates; the loser replays after the winner commits."""
    person = _person(admin_session, tenant_a)
    person_id = person.id
    tenant_id = tenant_a.id
    admin_session.commit()
    gate = Barrier(2, timeout=30)
    SessionLocal = sessionmaker(bind=admin_engine, autocommit=False, autoflush=False)

    def worker() -> str:
        db = SessionLocal()
        try:
            target = ApplicationLifecycleTarget(
                tenant_id=tenant_id,
                person_id=person_id,
                desired_state="suspended",
                external_subject=ExternalSubjectTarget(
                    provider_binding="customer-keycloak",
                    issuer="https://idp.customer.example/realms/customer",
                    subject="ConcurrentSubject",
                ),
            )
            gate.wait()
            result = plan(db, tenant_id=tenant_id, idempotency_key="concurrent-command", target=target)
            db.commit()
            return str(result.operation_ref)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        refs = {future.result(timeout=45) for future in (executor.submit(worker), executor.submit(worker))}
    assert len(refs) == 1


def test_apply_requires_exact_plan_and_revokes_live_sessions(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    session = AuthSession(
        tenant_id=tenant_a.id,
        person_id=person.id,
        token_hash="a" * 64,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    admin_session.add(session)
    admin_session.flush()  # an already-issued session, not a pending test-only object
    saved = plan(
        admin_session,
        tenant_id=tenant_a.id,
        idempotency_key="command-1",
        target=_target(tenant_a, person),
    )

    result = apply(
        admin_session,
        tenant_id=tenant_a.id,
        operation_ref=saved.operation_ref,
        idempotency_key="command-1",
        target=_target(tenant_a, person),
        target_digest=saved.target_digest,
        expected_state_digest=saved.expected_state_digest,
        plan_digest=saved.plan_digest,
    )

    assert result.operation_state == "applied"
    assert result.result_state["account_status"] == "suspended"
    assert result.result_state["external_identity_binding_state"] == "disabled"
    assert person.status == "suspended"
    assert session.revoked_at is not None


def test_apply_refuses_provider_mismatch_before_binding_mutation(
    admin_session,
    tenant_a,
    monkeypatch,
):
    from app.config import settings
    from app.models.external_identity import ExternalIdentityBinding

    person = _person(admin_session, tenant_a)
    target = _target(tenant_a, person, state="active")
    saved = plan(
        admin_session,
        tenant_id=tenant_a.id,
        idempotency_key="provider-mismatch",
        target=target,
    )
    monkeypatch.setattr(
        settings,
        "oidc_issuer",
        "https://idp.different.example/realms/customer",
    )

    with pytest.raises(ApplicationLifecycleError) as refusal:
        apply(
            admin_session,
            tenant_id=tenant_a.id,
            operation_ref=saved.operation_ref,
            idempotency_key="provider-mismatch",
            target=target,
            target_digest=saved.target_digest,
            expected_state_digest=saved.expected_state_digest,
            plan_digest=saved.plan_digest,
        )

    assert refusal.value.code == "provider_binding_unknown"
    assert admin_session.scalars(select(ExternalIdentityBinding)).all() == []
    assert person.status == "active"


def test_apply_replay_returns_stored_result_without_overwriting_later_local_state(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    target = _target(tenant_a, person)
    saved = plan(admin_session, tenant_id=tenant_a.id, idempotency_key="command-1", target=target)
    first = _apply_plan(admin_session, tenant_a, target)
    person.status = "active"  # a later local owner decision
    admin_session.flush()

    replay = apply(
        admin_session,
        tenant_id=tenant_a.id,
        operation_ref=saved.operation_ref,
        idempotency_key="command-1",
        target=target,
        target_digest=saved.target_digest,
        expected_state_digest=saved.expected_state_digest,
        plan_digest=saved.plan_digest,
    )

    assert replay == first
    assert person.status == "active"


def test_apply_refuses_when_expected_account_state_changed(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    target = _target(tenant_a, person)
    saved = plan(admin_session, tenant_id=tenant_a.id, idempotency_key="command-1", target=target)
    person.status = "suspended"
    admin_session.flush()

    with pytest.raises(ApplicationLifecycleError) as refusal:
        apply(
            admin_session,
            tenant_id=tenant_a.id,
            operation_ref=saved.operation_ref,
            idempotency_key="command-1",
            target=target,
            target_digest=saved.target_digest,
            expected_state_digest=saved.expected_state_digest,
            plan_digest=saved.plan_digest,
        )
    assert refusal.value.code == "expected_state_changed"


def test_observe_and_cancel_take_only_operation_identity(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    target = _target(tenant_a, person)
    saved = plan(admin_session, tenant_id=tenant_a.id, idempotency_key="command-1", target=target)

    seen = observe(admin_session, tenant_id=tenant_a.id, operation_ref=saved.operation_ref)
    assert seen.target == saved.target
    assert seen.operation_state == "planned"
    assert seen.converged is False

    stopped = cancel(admin_session, tenant_id=tenant_a.id, operation_ref=saved.operation_ref)
    assert stopped.operation_state == "cancelled"
    assert cancel(admin_session, tenant_id=tenant_a.id, operation_ref=saved.operation_ref) == stopped
    with pytest.raises(ApplicationLifecycleError) as refusal:
        apply(
            admin_session,
            tenant_id=tenant_a.id,
            operation_ref=saved.operation_ref,
            idempotency_key="command-1",
            target=target,
            target_digest=saved.target_digest,
            expected_state_digest=saved.expected_state_digest,
            plan_digest=saved.plan_digest,
        )
    assert refusal.value.code == "operation_cancelled"


def test_applied_operation_has_no_unsafe_cancel_inverse(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    result = _apply_plan(admin_session, tenant_a, _target(tenant_a, person))
    with pytest.raises(ApplicationLifecycleError) as refusal:
        cancel(admin_session, tenant_id=tenant_a.id, operation_ref=result.operation_ref)
    assert refusal.value.code == "operation_not_cancellable"


def test_plan_fields_are_immutable_even_through_raw_sql(admin_session, tenant_a):
    person = _person(admin_session, tenant_a)
    saved = plan(
        admin_session,
        tenant_id=tenant_a.id,
        idempotency_key="command-1",
        target=_target(tenant_a, person),
    )
    with pytest.raises(Exception, match="plan fields are immutable"):
        admin_session.execute(
            text(
                "UPDATE managed_application_lifecycle_operations "
                "SET target_digest = :digest WHERE id = :operation_ref"
            ),
            {"digest": "sha256:" + "0" * 64, "operation_ref": saved.operation_ref},
        )
        admin_session.flush()


def test_operation_is_invisible_under_another_tenant_rls(
    admin_session,
    app_user_session,
    tenant_a,
    tenant_b,
):
    person = _person(admin_session, tenant_a)
    saved = plan(
        admin_session,
        tenant_id=tenant_a.id,
        idempotency_key="command-1",
        target=_target(tenant_a, person),
    )
    admin_session.commit()

    app_user_session.execute(
        text("SELECT set_config('app.current_tenant', :tenant, true)"),
        {"tenant": str(tenant_b.id)},
    )
    assert (
        app_user_session.scalars(
            select(ManagedApplicationLifecycleOperation).where(
                ManagedApplicationLifecycleOperation.id == saved.operation_ref
            )
        ).first()
        is None
    )
