"""Tenant-scoped Person CRUD.

Demonstrates the canonical pattern: routes never read `tenant_id` from a payload or
URL; it always comes from `request.state.tenant`, set by `TenantResolverMiddleware`,
and enforced at the DB layer by RLS.

A request to `acme.app.com/people` lists ACME's people. A request to
`widgets.app.com/people` with the SAME ID will 404 even if the ID exists in ACME —
because RLS filters it out before the row reaches the application.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.person import Person
from app.models.tenant import Tenant

router = APIRouter(
    prefix="/people",
    tags=["people"],
    dependencies=[Depends(require_tenant)],
)


class PersonCreate(BaseModel):
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)


class PersonRead(BaseModel):
    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    model_config = {"from_attributes": True}


@router.post("", response_model=PersonRead, status_code=status.HTTP_201_CREATED)
def create_person(
    payload: PersonCreate,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
) -> Person:
    person = Person(
        tenant_id=tenant.id,  # never from payload — always from request state
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
    )
    db.add(person)
    try:
        db.flush()
        db.refresh(person)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered") from exc
    return person


@router.get("", response_model=list[PersonRead])
def list_people(db: Session = Depends(get_db)) -> list[Person]:
    # No explicit tenant filter — RLS does it. If RLS were misconfigured this would
    # leak; the cross-tenant test catches that.
    return list(db.scalars(select(Person).order_by(Person.created_at.desc())).all())


@router.get("/{person_id}", response_model=PersonRead)
def get_person(person_id: UUID, db: Session = Depends(get_db)) -> Person:
    person = db.get(Person, person_id)
    if person is None:
        raise HTTPException(status_code=404, detail="Person not found")
    return person


@router.delete("/{person_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_person(person_id: UUID, db: Session = Depends(get_db)) -> None:
    person = db.get(Person, person_id)
    if person is None:
        raise HTTPException(status_code=404, detail="Person not found")
    db.delete(person)
