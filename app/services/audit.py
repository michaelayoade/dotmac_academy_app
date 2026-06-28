"""Audit event helpers."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.rbac import AuditEvent


def write_audit_event(
    db: Session,
    *,
    tenant_id: UUID,
    actor_person_id: UUID | None,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    details: dict[str, object] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        tenant_id=tenant_id,
        actor_person_id=actor_person_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details or {},
    )
    db.add(event)
    db.flush()
    return event


def list_events(
    db: Session,
    *,
    tenant_id: UUID,
    limit: int = 100,
    offset: int = 0,
    action: str | None = None,
    actor_person_id: UUID | None = None,
) -> list[AuditEvent]:
    """Return audit events for a tenant, newest first.

    Keyword-only args. Optional filters:
    - action: exact match on AuditEvent.action
    - actor_person_id: exact match on AuditEvent.actor_person_id
    """
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if actor_person_id is not None:
        stmt = stmt.where(AuditEvent.actor_person_id == actor_person_id)
    return list(db.scalars(stmt).all())
