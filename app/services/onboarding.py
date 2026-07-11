"""Onboarding workflow — the checklist an accepted applicant works through.

Seeded when an applicant enters ``onboarding``; enrolment is gated on every
task being ``done``. Repo convention: ``db`` + explicit ids, ``flush`` not
``commit``, domain exceptions for the router. RLS scopes reads to the tenant.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.onboarding import TASK_STATUSES, OnboardingTask
from app.services.exceptions import BadRequestError, NotFoundError

# Default onboarding checklist (key, label, order). Non-billing per scope.
DEFAULT_TASKS: tuple[tuple[str, str], ...] = (
    ("entrance_assessment", "Complete the entrance assessment"),
    ("confirm_details", "Confirm your enrolment details"),
    ("orientation", "Review the programme orientation"),
)


def seed_tasks(db: Session, *, tenant_id: UUID, applicant_id: UUID) -> list[OnboardingTask]:
    """Create the default onboarding tasks for an applicant. Idempotent."""
    existing = {
        t.key: t
        for t in db.scalars(
            select(OnboardingTask)
            .where(OnboardingTask.tenant_id == tenant_id)
            .where(OnboardingTask.applicant_id == applicant_id)
        ).all()
    }
    for order, (key, label) in enumerate(DEFAULT_TASKS):
        if key in existing:
            continue
        db.add(
            OnboardingTask(
                tenant_id=tenant_id,
                applicant_id=applicant_id,
                key=key,
                label=label,
                order_index=order,
                status="pending",
            )
        )
    db.flush()
    return list_tasks(db, tenant_id=tenant_id, applicant_id=applicant_id)


def list_tasks(db: Session, *, tenant_id: UUID, applicant_id: UUID) -> list[OnboardingTask]:
    return list(
        db.scalars(
            select(OnboardingTask)
            .where(OnboardingTask.tenant_id == tenant_id)
            .where(OnboardingTask.applicant_id == applicant_id)
            .order_by(OnboardingTask.order_index, OnboardingTask.created_at)
        ).all()
    )


def get_task(db: Session, *, task_id: UUID) -> OnboardingTask:
    task = db.get(OnboardingTask, task_id)
    if task is None:  # missing or hidden by RLS
        raise NotFoundError("Onboarding task not found.")
    return task


def set_task_status(db: Session, *, task_id: UUID, status: str, now: datetime | None = None) -> OnboardingTask:
    if status not in TASK_STATUSES:
        raise BadRequestError(f"Unknown task status: {status}")
    task = get_task(db, task_id=task_id)
    task.status = status
    task.completed_at = (now or datetime.now(UTC)) if status == "done" else None
    db.flush()
    return task


def complete_task_by_key(db: Session, *, tenant_id: UUID, applicant_id: UUID, key: str) -> OnboardingTask | None:
    """Mark a task done by key (used when a step self-completes, e.g. a passed
    entrance assessment). Returns the task, or None if the applicant has no such task."""
    task = db.scalars(
        select(OnboardingTask)
        .where(OnboardingTask.tenant_id == tenant_id)
        .where(OnboardingTask.applicant_id == applicant_id)
        .where(OnboardingTask.key == key)
    ).first()
    if task is None:
        return None
    return set_task_status(db, task_id=task.id, status="done")


def is_complete(db: Session, *, tenant_id: UUID, applicant_id: UUID) -> bool:
    """True when the applicant has onboarding tasks and all are done."""
    tasks = list_tasks(db, tenant_id=tenant_id, applicant_id=applicant_id)
    return bool(tasks) and all(t.status == "done" for t in tasks)
