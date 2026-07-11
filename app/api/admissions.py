"""Admissions API — public application intake + admin pipeline management.

``POST /admissions/apply`` is PUBLIC (no login): the tenant is resolved from the
host by ``TenantResolverMiddleware`` and primed for RLS by ``get_db``, exactly
like ``POST /auth/register``. Everything else is admin-only.
"""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role, require_tenant
from app.models.admissions import Applicant
from app.models.onboarding import OnboardingTask
from app.models.person import Person
from app.models.tenant import Tenant
from app.services import admissions as admissions_service
from app.services import onboarding as onboarding_service

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
    # Entrance-assessment result (the candidate competency profile).
    cohort_id: UUID | None = None
    assessment_score: float | None = None
    assessment_level: str | None = None
    assessment_profile: dict | None = None
    assessment_taken_at: datetime | None = None
    assessment_time_exceeded: bool = False
    # Validity: False = the sitting carries NO SIGNAL (near-chance, or too fast to
    # have engaged). Do not read such a score as a weak candidate — it is an
    # absence of data, and it is excluded from score-ranked listings.
    assessment_valid: bool | None = None
    assessment_invalid_reason: str | None = None
    assessment_deadline: datetime | None = None
    invite_sent_at: datetime | None = None
    assessment_reset_count: int = 0

    # --- the evaluable application profile ---
    date_of_birth: date | None = None
    state: str | None = None
    city: str | None = None
    highest_qualification: str | None = None
    field_of_study: str | None = None
    years_experience: int | None = None
    current_role: str | None = None
    has_device: bool | None = None
    has_internet: bool | None = None
    can_work_at_height: bool | None = None
    available_from: date | None = None
    heard_from: str | None = None
    cv_url: str | None = None
    # Can this candidate actually be evaluated yet?
    profile_complete: bool = False
    missing_profile_fields: list[str] = []

    model_config = {"from_attributes": True}


class ApplicantTransition(BaseModel):
    to_status: str = Field(min_length=1, max_length=20)
    notes: str | None = Field(default=None, max_length=1000)


class ApplicantEnroll(BaseModel):
    cohort_id: UUID


class OnboardingTaskRead(BaseModel):
    id: UUID
    key: str
    label: str
    order_index: int
    status: str
    completed_at: datetime | None = None
    model_config = {"from_attributes": True}


class OnboardingTaskUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=10)


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
    cohort_id: UUID | None = Query(default=None),
    rank: bool = Query(default=False, description="Order by entrance-assessment score, best first"),
    db: Session = Depends(get_db),
    _: Person = Depends(require_role("admin")),
) -> list[Applicant]:
    return admissions_service.list_applicants(db, status=status, cohort_id=cohort_id, rank_by_score=rank)


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
    return admissions_service.enroll_applicant(db, applicant_id=applicant_id, cohort_id=payload.cohort_id)


@router.get("/{applicant_id}/onboarding", response_model=list[OnboardingTaskRead])
def list_onboarding_tasks(
    applicant_id: UUID,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
    _: Person = Depends(require_role("admin")),
) -> list[OnboardingTask]:
    """The applicant's onboarding checklist, ordered."""
    return onboarding_service.list_tasks(db, tenant_id=tenant.id, applicant_id=applicant_id)


@router.post("/onboarding-tasks/{task_id}", response_model=OnboardingTaskRead)
def update_onboarding_task(
    task_id: UUID,
    payload: OnboardingTaskUpdate,
    db: Session = Depends(get_db),
    _: Person = Depends(require_role("admin")),
) -> object:
    """Mark an onboarding task done (or back to pending)."""
    return onboarding_service.set_task_status(db, task_id=task_id, status=payload.status)
