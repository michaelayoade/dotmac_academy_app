"""Platform-admin endpoints — provision, suspend, delete tenants.

Reachable only on the platform root domain (no subdomain). Uses `get_platform_db` which
connects with `platform_api` — an online role with explicit grants and no RLS bypass.

This is a skeleton. Real impl needs:
- Platform admin authentication (separate auth from tenant users)
- Owner user provisioning in the same transaction as tenant create
- Audit log entry on every state change
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_platform_db, require_platform_admin
from app.models.tenant import Tenant

router = APIRouter(
    prefix="/platform/tenants",
    tags=["platform"],
    dependencies=[Depends(require_platform_admin)],
)


class TenantCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    name: str = Field(min_length=1, max_length=120)


class TenantRead(BaseModel):
    id: UUID
    slug: str
    name: str
    is_active: bool
    model_config = {"from_attributes": True}


@router.post("", response_model=TenantRead, status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreate, db: Session = Depends(get_platform_db)) -> Tenant:
    tenant = Tenant(slug=payload.slug, name=payload.name)
    db.add(tenant)
    try:
        db.flush()
        db.refresh(tenant)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Slug already in use") from exc
    return tenant


@router.get("", response_model=list[TenantRead])
def list_tenants(db: Session = Depends(get_platform_db)) -> list[Tenant]:
    return list(db.scalars(select(Tenant).order_by(Tenant.created_at.desc())).all())


@router.get("/{tenant_id}", response_model=TenantRead)
def get_tenant(tenant_id: UUID, db: Session = Depends(get_platform_db)) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant
