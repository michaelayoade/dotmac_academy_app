"""Authenticated Integrator adapter for Academy-owned account lifecycle."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.tenant import Tenant
from app.services import managed_application_lifecycle as lifecycle
from app.services.erp_integration_security import IntegrationAuthError, verify_managed_lifecycle_request

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/integrations/application-lifecycle",
    tags=["managed-application-lifecycle"],
    dependencies=[Depends(require_tenant)],
)


class ExternalSubjectTarget(BaseModel):
    provider_binding: str = Field(min_length=1, max_length=80)
    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=255)

    model_config = {"extra": "forbid"}

    @field_validator("provider_binding", "issuer", "subject")
    @classmethod
    def exact_nonblank_text(cls, value: str) -> str:
        exact = value.strip()
        if not exact or any(ord(char) < 32 or ord(char) == 127 for char in exact):
            raise ValueError("external subject values must be non-blank and contain no control characters")
        return exact


class ApplicationLifecycleTarget(BaseModel):
    tenant_id: UUID
    person_id: UUID
    desired_state: Literal["active", "suspended"]
    external_subject: ExternalSubjectTarget

    model_config = {"extra": "forbid"}

    def to_domain(self) -> lifecycle.ApplicationLifecycleTarget:
        return lifecycle.ApplicationLifecycleTarget(
            tenant_id=self.tenant_id,
            person_id=self.person_id,
            desired_state=self.desired_state,
            external_subject=lifecycle.ExternalSubjectTarget(
                provider_binding=self.external_subject.provider_binding,
                issuer=self.external_subject.issuer,
                subject=self.external_subject.subject,
            ),
        )


class PlanRequest(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=120)
    target: ApplicationLifecycleTarget

    model_config = {"extra": "forbid"}


class PlanResponse(BaseModel):
    operation_ref: UUID
    target: dict[str, object]
    target_digest: str
    expected_state: dict[str, object]
    expected_state_digest: str
    plan_digest: str
    actions: tuple[str, ...]


class ApplyRequest(BaseModel):
    operation_ref: UUID
    idempotency_key: str = Field(min_length=1, max_length=120)
    target: ApplicationLifecycleTarget
    target_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_state_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    model_config = {"extra": "forbid"}


class ApplyResponse(BaseModel):
    operation_ref: UUID
    operation_state: Literal["applied"]
    target_digest: str
    plan_digest: str
    result_state: dict[str, object]
    result_state_digest: str
    applied_at: datetime


class OperationRequest(BaseModel):
    operation_ref: UUID

    model_config = {"extra": "forbid"}


class ObserveResponse(BaseModel):
    operation_ref: UUID
    operation_state: Literal["planned", "applied", "cancelled"]
    target: dict[str, object]
    target_digest: str
    expected_state_digest: str
    plan_digest: str
    current_state: dict[str, object]
    current_state_digest: str
    converged: bool
    applied_at: datetime | None
    cancelled_at: datetime | None


class CancelResponse(BaseModel):
    operation_ref: UUID
    operation_state: Literal["cancelled"]
    cancelled_at: datetime


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message}})


def _authenticate(request: Request, body: bytes) -> JSONResponse | None:
    try:
        verify_managed_lifecycle_request(
            body=body,
            timestamp=request.headers.get("X-Webhook-Timestamp"),
            signature=request.headers.get("X-Webhook-Signature-256"),
        )
    except IntegrationAuthError as exc:
        if exc.code == "integration_disabled":
            return _error(503, exc.code, "Managed application lifecycle is unavailable")
        if exc.code == "request_too_large":
            return _error(413, exc.code, "Request body is too large")
        return _error(401, exc.code, "Request authentication failed")
    return None


def _payload(model: type[BaseModel], body: bytes) -> BaseModel | JSONResponse:
    try:
        return model.model_validate_json(body)
    except ValidationError as exc:
        malformed = any(error["type"] == "json_invalid" for error in exc.errors())
        return _error(
            400 if malformed else 422,
            "malformed_json" if malformed else "invalid_request",
            "Request body is not valid JSON" if malformed else "Request fields are invalid",
        )


def _domain_error(exc: lifecycle.ApplicationLifecycleError) -> JSONResponse:
    return _error(exc.status_code, exc.code, exc.message)


@router.post("/plan", response_model=PlanResponse)
async def plan_application_lifecycle(
    request: Request,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
):
    body = await request.body()
    refused = _authenticate(request, body)
    if refused is not None:
        return refused
    parsed = _payload(PlanRequest, body)
    if isinstance(parsed, JSONResponse):
        return parsed
    assert isinstance(parsed, PlanRequest)
    try:
        result = lifecycle.plan(
            db,
            tenant_id=tenant.id,
            idempotency_key=parsed.idempotency_key,
            target=parsed.target.to_domain(),
        )
    except lifecycle.ApplicationLifecycleError as exc:
        return _domain_error(exc)
    return PlanResponse.model_validate(result, from_attributes=True)


@router.post("/apply", response_model=ApplyResponse)
async def apply_application_lifecycle(
    request: Request,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
):
    body = await request.body()
    refused = _authenticate(request, body)
    if refused is not None:
        return refused
    parsed = _payload(ApplyRequest, body)
    if isinstance(parsed, JSONResponse):
        return parsed
    assert isinstance(parsed, ApplyRequest)
    try:
        result = lifecycle.apply(
            db,
            tenant_id=tenant.id,
            operation_ref=parsed.operation_ref,
            idempotency_key=parsed.idempotency_key,
            target=parsed.target.to_domain(),
            target_digest=parsed.target_digest,
            expected_state_digest=parsed.expected_state_digest,
            plan_digest=parsed.plan_digest,
        )
    except lifecycle.ApplicationLifecycleError as exc:
        return _domain_error(exc)
    return ApplyResponse.model_validate(result, from_attributes=True)


@router.post("/observe", response_model=ObserveResponse)
async def observe_application_lifecycle(
    request: Request,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
):
    body = await request.body()
    refused = _authenticate(request, body)
    if refused is not None:
        return refused
    parsed = _payload(OperationRequest, body)
    if isinstance(parsed, JSONResponse):
        return parsed
    assert isinstance(parsed, OperationRequest)
    try:
        result = lifecycle.observe(db, tenant_id=tenant.id, operation_ref=parsed.operation_ref)
    except lifecycle.ApplicationLifecycleError as exc:
        return _domain_error(exc)
    return ObserveResponse.model_validate(result, from_attributes=True)


@router.post("/cancel", response_model=CancelResponse)
async def cancel_application_lifecycle(
    request: Request,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
):
    body = await request.body()
    refused = _authenticate(request, body)
    if refused is not None:
        return refused
    parsed = _payload(OperationRequest, body)
    if isinstance(parsed, JSONResponse):
        return parsed
    assert isinstance(parsed, OperationRequest)
    try:
        result = lifecycle.cancel(db, tenant_id=tenant.id, operation_ref=parsed.operation_ref)
    except lifecycle.ApplicationLifecycleError as exc:
        return _domain_error(exc)
    return CancelResponse.model_validate(result, from_attributes=True)


__all__ = ["router"]
