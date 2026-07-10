"""Admissions API — public application intake + admin pipeline management.

``POST /admissions/apply`` is PUBLIC (no login): the tenant is resolved from the
host by ``TenantResolverMiddleware`` and primed for RLS by ``get_db``, exactly
like ``POST /auth/register``. Everything else is admin-only.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role, require_tenant
from app.models.person import Person
from app.models.tenant import Tenant
from app.services import admissions as admissions_service

router = APIRouter(
    prefix="/admissions",
    tags=["admissions"],
    dependencies=[Depends(require_tenant)],
)


class ApplicationSubmit(BaseModel):
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    phone: str | None = Field(default=None, max_length=40)
    program: str | None = Field(default=None, max_length=120)


class ApplicantRead(BaseModel):
    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    phone: str | None
    program: str | None
    status: str
    source: str
    applied_on: date
    person_id: UUID | None = None
    model_config = {"from_attributes": True}


class ApplicantTransition(BaseModel):
    to_status: str = Field(min_length=1, max_length=20)
    notes: str | None = Field(default=None, max_length=1000)


class ApplicantEnroll(BaseModel):
    cohort_id: UUID


@router.post("/apply", response_model=ApplicantRead, status_code=status.HTTP_201_CREATED)
def apply(
    payload: ApplicationSubmit,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
) -> object:
    """Public application intake. Idempotent on email (a re-apply updates details)."""
    return admissions_service.submit_application(
        db,
        tenant_id=tenant.id,  # from request state, never the payload
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        phone=payload.phone,
        program=payload.program,
        source="website",
    )


@router.get("", response_model=list[ApplicantRead])
def list_applicants(
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: Person = Depends(require_role("admin")),
) -> list[object]:
    return admissions_service.list_applicants(db, status=status)


@router.get("/{applicant_id}", response_model=ApplicantRead)
def get_applicant(
    applicant_id: UUID,
    db: Session = Depends(get_db),
    _: Person = Depends(require_role("admin")),
) -> object:
    return admissions_service.get_applicant(db, applicant_id=applicant_id)


@router.post("/{applicant_id}/transition", response_model=ApplicantRead)
def transition_applicant(
    applicant_id: UUID,
    payload: ApplicantTransition,
    db: Session = Depends(get_db),
    _: Person = Depends(require_role("admin")),
) -> object:
    """Advance an applicant through the pipeline (screen / accept / reject / etc.)."""
    return admissions_service.transition_applicant(
        db,
        applicant_id=applicant_id,
        to_status=payload.to_status,
        notes=payload.notes,
    )


@router.post("/{applicant_id}/enroll", response_model=ApplicantRead)
def enroll_applicant(
    applicant_id: UUID,
    payload: ApplicantEnroll,
    db: Session = Depends(get_db),
    _: Person = Depends(require_role("admin")),
) -> object:
    """Enrol an onboarding applicant: create/reuse a Person + Enrollment."""
    return admissions_service.enroll_applicant(
        db, applicant_id=applicant_id, cohort_id=payload.cohort_id
    )
