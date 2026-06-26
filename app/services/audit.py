"""Audit event helpers."""

from __future__ import annotations

from uuid import UUID

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
