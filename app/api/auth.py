"""Authenticated single-Academy API session endpoints.

Account creation is intentionally absent. Administrators invite users and
applicants create credentials through the single-use onboarding flow.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant, require_user_auth
from app.models.person import Person
from app.models.tenant import Tenant
from app.services import web_auth

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_tenant)])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CurrentUserResponse(BaseModel):
    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    tenant_id: UUID


@router.post("/login", response_model=TokenResponse, responses={401: {"description": "Invalid credentials"}})
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(require_tenant),
) -> TokenResponse | JSONResponse:
    person = web_auth.authenticate(db, tenant.id, payload.email, payload.password)
    if person is None:
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})

    token = web_auth.start_session(db, tenant.id, person.id)
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
