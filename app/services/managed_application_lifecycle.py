"""Academy-owned managed application and external-binding lifecycle.

The endpoint is a product port, never a provider client. It applies an approved
exact subject to Academy's one local identity owner, then delegates account
status to the existing lifecycle owner. No provider I/O or claim mapping occurs
on this path.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.managed_application_lifecycle import ManagedApplicationLifecycleOperation
from app.models.person import Person
from app.services.external_identity import (
    bind_external_identity,
    binding_state_for_subject,
    disable_external_identity_binding,
)
from app.services.external_identity_config import configuration_matches
from app.services.lifecycle import set_account_status

DesiredState = Literal["active", "suspended"]
OperationState = Literal["planned", "applied", "cancelled"]

CAPABILITY_ID = "academy.application.lifecycle.v1"
TARGET_SCHEMA = "academy.application-lifecycle.target/v1"
EXPECTED_STATE_SCHEMA = "academy.application-lifecycle.expected-state/v1"
PLAN_SCHEMA = "academy.application-lifecycle.plan/v1"
RESULT_SCHEMA = "academy.application-lifecycle.result/v1"

STABLE_FAILURE_CODES = frozenset(
    {
        "expected_state_changed",
        "idempotency_conflict",
        "operation_cancelled",
        "operation_not_cancellable",
        "operation_not_found",
        "person_not_found",
        "plan_mismatch",
        "provider_binding_unknown",
        "tenant_mismatch",
    }
)


class ApplicationLifecycleError(ValueError):
    """Stable product refusal returned by the thin HTTP adapter."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        if code not in STABLE_FAILURE_CODES:
            raise ValueError(f"undeclared application lifecycle failure code: {code}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ExternalSubjectTarget:
    provider_binding: str
    issuer: str
    subject: str


@dataclass(frozen=True, slots=True)
class ApplicationLifecycleTarget:
    tenant_id: UUID
    person_id: UUID
    desired_state: DesiredState
    external_subject: ExternalSubjectTarget


@dataclass(frozen=True, slots=True)
class PlanResult:
    operation_ref: UUID
    target: dict[str, object]
    target_digest: str
    expected_state: dict[str, object]
    expected_state_digest: str
    plan_digest: str
    actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApplyResult:
    operation_ref: UUID
    operation_state: Literal["applied"]
    target_digest: str
    plan_digest: str
    result_state: dict[str, object]
    result_state_digest: str
    applied_at: datetime


@dataclass(frozen=True, slots=True)
class ObserveResult:
    operation_ref: UUID
    operation_state: OperationState
    target: dict[str, object]
    target_digest: str
    expected_state_digest: str
    plan_digest: str
    current_state: dict[str, object]
    current_state_digest: str
    converged: bool
    applied_at: datetime | None
    cancelled_at: datetime | None


@dataclass(frozen=True, slots=True)
class CancelResult:
    operation_ref: UUID
    operation_state: Literal["cancelled"]
    cancelled_at: datetime


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact_text(value: str, *, field: str, limit: int) -> str:
    exact = value.strip()
    if not exact:
        raise ValueError(f"{field} must not be blank")
    if len(exact) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in exact):
        raise ValueError(f"{field} contains control characters")
    return exact


def canonical_target(target: ApplicationLifecycleTarget) -> dict[str, object]:
    """Return the one target spelling that may be hashed or stored.

    Issuer and subject remain case-sensitive.  Only outer whitespace is
    removed, matching the kernel external-identity contract and refusing the
    email/name matching that would permit account takeover.
    """

    if target.desired_state not in {"active", "suspended"}:
        raise ValueError("desired_state must be active or suspended")
    return {
        "schema": TARGET_SCHEMA,
        "tenant_id": str(target.tenant_id),
        "person_id": str(target.person_id),
        "desired_state": target.desired_state,
        "external_subject": {
            "provider_binding": _exact_text(
                target.external_subject.provider_binding,
                field="provider_binding",
                limit=80,
            ),
            "issuer": _exact_text(target.external_subject.issuer, field="issuer", limit=512),
            "subject": _exact_text(target.external_subject.subject, field="subject", limit=255),
        },
    }


def _expected_state(person: Person) -> dict[str, object]:
    return {
        "schema": EXPECTED_STATE_SCHEMA,
        "tenant_id": str(person.tenant_id),
        "person_id": str(person.id),
        "account_status": person.status,
    }


def _result_state(person: Person, *, binding_state: str) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "tenant_id": str(person.tenant_id),
        "person_id": str(person.id),
        "account_status": person.status,
        "external_identity_binding_state": binding_state,
    }


def _actions(*, current: str, desired: DesiredState) -> tuple[str, ...]:
    account = "account.noop"
    if current != desired:
        account = "account.activate" if desired == "active" else "account.suspend"
    if desired == "active":
        return ("external-identity.bind-or-enable", account)
    return ("external-identity.bind-or-enable", "external-identity.disable", account)


def _external_subject(document: dict[str, object]) -> tuple[str, str, str]:
    external = document.get("external_subject")
    if not isinstance(external, dict):
        raise RuntimeError("stored managed lifecycle target has no external subject")
    provider_binding = external.get("provider_binding")
    issuer = external.get("issuer")
    subject = external.get("subject")
    if not all(isinstance(value, str) for value in (provider_binding, issuer, subject)):
        raise RuntimeError("stored managed lifecycle external subject is invalid")
    return cast(str, provider_binding), cast(str, issuer), cast(str, subject)


def _plan_document(*, target_digest: str, expected_state_digest: str, actions: tuple[str, ...]) -> dict[str, object]:
    return {
        "schema": PLAN_SCHEMA,
        "capability_id": CAPABILITY_ID,
        "target_digest": target_digest,
        "expected_state_digest": expected_state_digest,
        "actions": list(actions),
    }


def _row_plan(row: ManagedApplicationLifecycleOperation) -> PlanResult:
    status = str(row.expected_state["account_status"])
    if row.desired_state not in {"active", "suspended"}:  # database check plus typed refusal
        raise RuntimeError("stored managed lifecycle desired_state is invalid")
    desired = cast(DesiredState, row.desired_state)
    return PlanResult(
        operation_ref=row.id,
        target=dict(row.target),
        target_digest=row.target_digest,
        expected_state=dict(row.expected_state),
        expected_state_digest=row.expected_state_digest,
        plan_digest=row.plan_digest,
        actions=_actions(current=status, desired=desired),
    )


def plan(
    db: Session,
    *,
    tenant_id: UUID,
    idempotency_key: str,
    target: ApplicationLifecycleTarget,
) -> PlanResult:
    """Persist or replay the immutable local PLAN for one exact target."""

    if target.tenant_id != tenant_id:
        raise ApplicationLifecycleError(
            "tenant_mismatch",
            "target tenant does not match the authenticated Academy tenant",
            status_code=409,
        )
    stable_key = _exact_text(idempotency_key, field="idempotency_key", limit=120)
    target_document = canonical_target(target)
    target_digest = _digest(target_document)
    provider_binding, issuer, _subject = _external_subject(target_document)
    if not configuration_matches(
        provider_binding=provider_binding,
        issuer=issuer,
    ):
        raise ApplicationLifecycleError(
            "provider_binding_unknown",
            "the target does not match Academy's installed provider registration",
            status_code=409,
        )

    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(Person.id == target.person_id)
    ).first()
    if person is None:
        raise ApplicationLifecycleError(
            "person_not_found",
            "the target person does not exist in this Academy tenant",
            status_code=404,
        )
    expected = _expected_state(person)
    expected_digest = _digest(expected)
    actions = _actions(current=person.status, desired=target.desired_state)
    plan_digest = _digest(
        _plan_document(
            target_digest=target_digest,
            expected_state_digest=expected_digest,
            actions=actions,
        )
    )
    operation_ref = uuid4()
    inserted = db.execute(
        insert(ManagedApplicationLifecycleOperation)
        .values(
            id=operation_ref,
            tenant_id=tenant_id,
            person_id=target.person_id,
            idempotency_key=stable_key,
            target=target_document,
            target_digest=target_digest,
            expected_state=expected,
            expected_state_digest=expected_digest,
            plan_digest=plan_digest,
            desired_state=target.desired_state,
            operation_state="planned",
        )
        .on_conflict_do_nothing(
            index_elements=["tenant_id", "idempotency_key"],
        )
        .returning(ManagedApplicationLifecycleOperation.id)
    ).scalar_one_or_none()
    if inserted is not None:
        row = db.get(ManagedApplicationLifecycleOperation, inserted)
        if row is None:  # pragma: no cover - INSERT RETURNING guarantees it
            raise RuntimeError("inserted managed lifecycle operation disappeared")
        return _row_plan(row)

    existing = db.scalars(
        select(ManagedApplicationLifecycleOperation)
        .where(ManagedApplicationLifecycleOperation.tenant_id == tenant_id)
        .where(ManagedApplicationLifecycleOperation.idempotency_key == stable_key)
    ).first()
    if existing is None:  # pragma: no cover - unique conflict guarantees a row
        raise RuntimeError("managed lifecycle idempotency conflict has no row")
    if existing.target_digest != target_digest or existing.target != target_document:
        raise ApplicationLifecycleError(
            "idempotency_conflict",
            "the idempotency key already names a different target",
            status_code=409,
        )
    return _row_plan(existing)


def _locked_operation(
    db: Session,
    *,
    tenant_id: UUID,
    operation_ref: UUID,
) -> ManagedApplicationLifecycleOperation:
    row = db.scalars(
        select(ManagedApplicationLifecycleOperation)
        .where(ManagedApplicationLifecycleOperation.tenant_id == tenant_id)
        .where(ManagedApplicationLifecycleOperation.id == operation_ref)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if row is None:
        raise ApplicationLifecycleError(
            "operation_not_found",
            "the managed lifecycle operation does not exist in this Academy tenant",
            status_code=404,
        )
    return row


def apply(
    db: Session,
    *,
    tenant_id: UUID,
    operation_ref: UUID,
    idempotency_key: str,
    target: ApplicationLifecycleTarget,
    target_digest: str,
    expected_state_digest: str,
    plan_digest: str,
    now: datetime | None = None,
) -> ApplyResult:
    """Apply exactly the persisted plan, or replay its immutable result."""

    row = _locked_operation(db, tenant_id=tenant_id, operation_ref=operation_ref)
    supplied_target = canonical_target(target)
    stable_key = _exact_text(idempotency_key, field="idempotency_key", limit=120)
    if (
        target.tenant_id != tenant_id
        or row.person_id != target.person_id
        or row.idempotency_key != stable_key
        or row.target != supplied_target
        or row.target_digest != target_digest
        or row.expected_state_digest != expected_state_digest
        or row.plan_digest != plan_digest
    ):
        raise ApplicationLifecycleError(
            "plan_mismatch",
            "apply does not exactly match the persisted Academy plan",
            status_code=409,
        )
    if row.operation_state == "cancelled":
        raise ApplicationLifecycleError(
            "operation_cancelled",
            "a cancelled Academy plan cannot be applied",
            status_code=409,
        )
    if row.operation_state == "applied":
        if row.result_state is None or row.result_state_digest is None or row.applied_at is None:
            raise RuntimeError("applied managed lifecycle operation has incomplete evidence")
        return ApplyResult(
            operation_ref=row.id,
            operation_state="applied",
            target_digest=row.target_digest,
            plan_digest=row.plan_digest,
            result_state=dict(row.result_state),
            result_state_digest=row.result_state_digest,
            applied_at=row.applied_at,
        )

    provider_binding, issuer, subject = _external_subject(row.target)
    if not configuration_matches(
        provider_binding=provider_binding,
        issuer=issuer,
    ):
        raise ApplicationLifecycleError(
            "provider_binding_unknown",
            "the approved external subject does not match Academy's installed provider registration",
            status_code=409,
        )

    binding = bind_external_identity(
        db,
        tenant_id=tenant_id,
        person_id=row.person_id,
        provider_binding=provider_binding,
        issuer=issuer,
        subject=subject,
        bound_by=f"integrator:{row.id}",
        reason="approved Academy managed application lifecycle operation",
    )
    person = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant_id)
        .where(Person.id == row.person_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if person is None:
        raise ApplicationLifecycleError(
            "person_not_found",
            "the target person no longer exists in this Academy tenant",
            status_code=404,
        )
    if _digest(_expected_state(person)) != row.expected_state_digest:
        raise ApplicationLifecycleError(
            "expected_state_changed",
            "the Academy account changed after plan; create and approve a new plan",
            status_code=409,
        )

    changed = set_account_status(
        db,
        tenant_id=tenant_id,
        person_id=person.id,
        status=row.desired_state,
    )
    if row.desired_state == "suspended":
        binding = disable_external_identity_binding(
            db,
            tenant_id=tenant_id,
            binding_id=binding.id,
        )
    result = _result_state(
        changed,
        binding_state="active" if binding.is_active else "disabled",
    )
    applied_at = now or datetime.now(UTC)
    row.operation_state = "applied"
    row.result_state = result
    row.result_state_digest = _digest(result)
    row.applied_at = applied_at
    db.flush()
    return ApplyResult(
        operation_ref=row.id,
        operation_state="applied",
        target_digest=row.target_digest,
        plan_digest=row.plan_digest,
        result_state=dict(result),
        result_state_digest=row.result_state_digest,
        applied_at=applied_at,
    )


def observe(
    db: Session,
    *,
    tenant_id: UUID,
    operation_ref: UUID,
) -> ObserveResult:
    """Observe from the durable operation; never accept a replacement target."""

    row = db.scalars(
        select(ManagedApplicationLifecycleOperation)
        .where(ManagedApplicationLifecycleOperation.tenant_id == tenant_id)
        .where(ManagedApplicationLifecycleOperation.id == operation_ref)
    ).first()
    if row is None:
        raise ApplicationLifecycleError(
            "operation_not_found",
            "the managed lifecycle operation does not exist in this Academy tenant",
            status_code=404,
        )
    person = db.scalars(select(Person).where(Person.tenant_id == tenant_id).where(Person.id == row.person_id)).first()
    if person is None:
        raise ApplicationLifecycleError(
            "person_not_found",
            "the target person no longer exists in this Academy tenant",
            status_code=404,
        )
    provider_binding, issuer, subject = _external_subject(row.target)
    current = _result_state(
        person,
        binding_state=binding_state_for_subject(
            db,
            tenant_id=tenant_id,
            person_id=row.person_id,
            provider_binding=provider_binding,
            issuer=issuer,
            subject=subject,
        ),
    )
    if row.operation_state not in {"planned", "applied", "cancelled"}:
        raise RuntimeError("stored managed lifecycle operation_state is invalid")
    state = cast(OperationState, row.operation_state)
    return ObserveResult(
        operation_ref=row.id,
        operation_state=state,
        target=dict(row.target),
        target_digest=row.target_digest,
        expected_state_digest=row.expected_state_digest,
        plan_digest=row.plan_digest,
        current_state=current,
        current_state_digest=_digest(current),
        converged=(
            person.status == row.desired_state
            and current["external_identity_binding_state"]
            == ("active" if row.desired_state == "active" else "disabled")
        ),
        applied_at=row.applied_at,
        cancelled_at=row.cancelled_at,
    )


def cancel(
    db: Session,
    *,
    tenant_id: UUID,
    operation_ref: UUID,
    now: datetime | None = None,
) -> CancelResult:
    """Cancel only an unapplied plan; applied state has no safe implicit inverse."""

    row = _locked_operation(db, tenant_id=tenant_id, operation_ref=operation_ref)
    if row.operation_state == "applied":
        raise ApplicationLifecycleError(
            "operation_not_cancellable",
            "applied account state has no safe inverse; approve a new desired state",
            status_code=409,
        )
    if row.operation_state == "cancelled":
        if row.cancelled_at is None:
            raise RuntimeError("cancelled managed lifecycle operation has no timestamp")
        return CancelResult(row.id, "cancelled", row.cancelled_at)
    cancelled_at = now or datetime.now(UTC)
    row.operation_state = "cancelled"
    row.cancelled_at = cancelled_at
    db.flush()
    return CancelResult(row.id, "cancelled", cancelled_at)


__all__ = [
    "CAPABILITY_ID",
    "STABLE_FAILURE_CODES",
    "ApplicationLifecycleError",
    "ApplicationLifecycleTarget",
    "ApplyResult",
    "CancelResult",
    "ExternalSubjectTarget",
    "ObserveResult",
    "PlanResult",
    "apply",
    "cancel",
    "canonical_target",
    "observe",
    "plan",
]
