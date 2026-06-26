"""Tenant-scoped auth endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant, require_user_auth
from app.models.auth import AuthSession, UserCredential
from app.models.person import Person
from app.models.rbac import PersonRole, Role
from app.models.tenant import Tenant
from app.services.security import hash_password, hash_token, issue_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_tenant)])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a password.


class CurrentUserResponse(BaseModel):
    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    tenant_id: UUID


@router.post("/register", response_model=CurrentUserResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
) -> CurrentUserResponse:
    person = Person(
        tenant_id=tenant.id,
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
    )
    db.add(person)
    try:
        db.flush()
        credential = UserCredential(
            tenant_id=tenant.id,
            person_id=person.id,
            email=payload.email,
            password_hash=hash_password(payload.password),
        )
        db.add(credential)
        db.flush()
        _assign_first_user_admin(db, tenant, person)
        db.refresh(person)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered") from exc
    return _current_user_response(person)


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
) -> TokenResponse:
    credential = db.scalars(
        select(UserCredential)
        .where(UserCredential.tenant_id == tenant.id)
        .where(UserCredential.email == payload.email)
    ).first()
    if credential is None or not verify_password(payload.password, credential.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token, expires_at = issue_access_token(credential.person_id, tenant.id)
    db.add(
        AuthSession(
            tenant_id=tenant.id,
            person_id=credential.person_id,
            token_hash=hash_token(token),
            expires_at=expires_at,
        )
    )
    db.flush()
    return TokenResponse(access_token=token)


@router.get("/me", response_model=CurrentUserResponse)
def me(person: Person = Depends(require_user_auth)) -> CurrentUserResponse:
    return _current_user_response(person)


def _current_user_response(person: Person) -> CurrentUserResponse:
    return CurrentUserResponse(
        id=person.id,
        email=person.email,
        first_name=person.first_name,
        last_name=person.last_name,
        tenant_id=person.tenant_id,
    )


def _assign_first_user_admin(db: Session, tenant: Tenant, person: Person) -> None:
    existing_assignment = db.scalars(
        select(PersonRole).where(PersonRole.tenant_id == tenant.id).limit(1)
    ).first()
    if existing_assignment is not None:
        return

    role = db.scalars(
        select(Role).where(Role.tenant_id == tenant.id).where(Role.slug == "admin")
    ).first()
    if role is None:
        role = Role(tenant_id=tenant.id, slug="admin", name="Admin")
        db.add(role)
        db.flush()
    db.add(PersonRole(tenant_id=tenant.id, person_id=person.id, role_id=role.id))
    db.flush()
