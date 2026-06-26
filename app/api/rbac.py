"""Tenant-scoped RBAC and audit endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role, require_tenant
from app.models.person import Person
from app.models.rbac import AuditEvent, PersonRole, Role
from app.models.tenant import Tenant
from app.services.audit import write_audit_event

router = APIRouter(prefix="/rbac", tags=["rbac"], dependencies=[Depends(require_tenant)])


class RoleCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    name: str = Field(min_length=1, max_length=120)


class RoleRead(BaseModel):
    id: UUID
    slug: str
    name: str
    model_config = {"from_attributes": True}


class RoleGrantRequest(BaseModel):
    person_id: UUID
    role_id: UUID


class AuditEventRead(BaseModel):
    id: UUID
    actor_person_id: UUID | None
    action: str
    entity_type: str
    entity_id: str | None
    details: dict[str, object]
    created_at: datetime
    model_config = {"from_attributes": True}


@router.post(
    "/roles",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
)
def create_role(
    payload: RoleCreate,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
    actor: Person = Depends(require_role("admin")),
) -> Role:
    role = Role(tenant_id=tenant.id, slug=payload.slug, name=payload.name)
    db.add(role)
    try:
        db.flush()
        db.refresh(role)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Role already exists") from exc
    write_audit_event(
        db,
        tenant_id=tenant.id,
        actor_person_id=actor.id,
        action="role.create",
        entity_type="role",
        entity_id=str(role.id),
        details={"slug": role.slug},
    )
    return role


@router.post("/role-grants", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def grant_role(
    payload: RoleGrantRequest,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
    actor: Person = Depends(require_role("admin")),
) -> None:
    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant.id).where(Person.id == payload.person_id)
    ).first()
    role = db.scalars(
        select(Role).where(Role.tenant_id == tenant.id).where(Role.id == payload.role_id)
    ).first()
    if person is None or role is None:
        raise HTTPException(status_code=404, detail="Person or role not found")

    db.add(PersonRole(tenant_id=tenant.id, person_id=person.id, role_id=role.id))
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Role already assigned") from exc
    write_audit_event(
        db,
        tenant_id=tenant.id,
        actor_person_id=actor.id,
        action="role.grant",
        entity_type="person_role",
        entity_id=str(person.id),
        details={"role_id": str(role.id)},
    )


@router.get("/audit-events", response_model=list[AuditEventRead])
def list_audit_events(
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
    _: Person = Depends(require_role("admin")),
) -> list[AuditEvent]:
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant.id)
            .order_by(AuditEvent.created_at.desc())
        ).all()
    )
