"""Announcement service.

All keyword-only after `db`. No db.commit() — callers/get_db own the tx.
create() flushes so the caller sees the new row (and emitted notifications/audit)
in the same session before get_db commits.
"""
from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.announcement import Announcement
from app.models.cohort import Enrollment
from app.services.audit import write_audit_event
from app.services.authoring import render_markdown
from app.services.notifications import notify_many

logger = logging.getLogger(__name__)


def create(
    db: Session,
    *,
    tenant_id: UUID,
    author_person_id: UUID,
    title: str,
    body_md: str,
    cohort_id: UUID | None = None,
) -> Announcement:
    body_html = render_markdown(body_md)
    ann = Announcement(
        tenant_id=tenant_id,
        cohort_id=cohort_id,
        author_person_id=author_person_id,
        title=title,
        body_md=body_md,
        body_html=body_html,
    )
    db.add(ann)
    db.flush()

    # Audience: cohort students if targeted, else all actively-enrolled persons.
    if cohort_id is not None:
        audience_ids = list(
            db.scalars(
                select(Enrollment.person_id)
                .where(Enrollment.tenant_id == tenant_id)
                .where(Enrollment.cohort_id == cohort_id)
                .where(Enrollment.status == "active")
                .where(Enrollment.role_in_cohort == "student")
            ).all()
        )
    else:
        audience_ids = list(
            db.scalars(
                select(Enrollment.person_id)
                .where(Enrollment.tenant_id == tenant_id)
                .where(Enrollment.status == "active")
                .distinct()
            ).all()
        )

    if audience_ids:
        # Best-effort fan-out: a notification insert failure must NOT roll back the
        # announcement. SAVEPOINT isolates it so a poisoned sub-tx can't break the
        # outer get_db commit.
        try:
            with db.begin_nested():
                notify_many(
                    db,
                    tenant_id=tenant_id,
                    person_ids=audience_ids,
                    kind="announcement",
                    title=title,
                    body="",
                    link="/announcements",
                )
        except Exception as exc:
            logger.warning("announcement notify fan-out failed: %s", exc)

    write_audit_event(
        db,
        tenant_id=tenant_id,
        actor_person_id=author_person_id,
        action="announcement.created",
        entity_type="announcement",
        entity_id=str(ann.id),
    )

    return ann


def for_person(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    limit: int = 20,
) -> list[Announcement]:
    """Tenant-wide (cohort_id IS NULL) OR cohorts the person is actively enrolled in."""
    enrolled_cohort_ids = list(
        db.scalars(
            select(Enrollment.cohort_id)
            .where(Enrollment.tenant_id == tenant_id)
            .where(Enrollment.person_id == person_id)
            .where(Enrollment.status == "active")
        ).all()
    )
    if enrolled_cohort_ids:
        cohort_filter = or_(
            Announcement.cohort_id.is_(None),
            Announcement.cohort_id.in_(enrolled_cohort_ids),
        )
    else:
        cohort_filter = Announcement.cohort_id.is_(None)

    return list(
        db.scalars(
            select(Announcement)
            .where(Announcement.tenant_id == tenant_id)
            .where(cohort_filter)
            .order_by(Announcement.created_at.desc())
            .limit(limit)
        ).all()
    )


def list_for_tenant(
    db: Session,
    *,
    tenant_id: UUID,
    limit: int = 50,
) -> list[Announcement]:
    return list(
        db.scalars(
            select(Announcement)
            .where(Announcement.tenant_id == tenant_id)
            .order_by(Announcement.created_at.desc())
            .limit(limit)
        ).all()
    )


def delete(
    db: Session,
    *,
    tenant_id: UUID,
    announcement_id: UUID,
) -> None:
    ann = db.scalars(
        select(Announcement)
        .where(Announcement.tenant_id == tenant_id)
        .where(Announcement.id == announcement_id)
    ).first()
    if ann is not None:
        db.delete(ann)
        db.flush()
