from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class ActivityAttempt(Base, TimestampMixin):
    """A learner's in-progress sitting of a randomized activity.

    For activities with a question pool (``Activity.question_count`` set), the
    subset and order of questions are fixed here when the learner opens the
    activity, so the submit grades exactly what was shown. One open (unsubmitted)
    attempt per (person, activity) at a time; submitting stamps ``submitted_at``
    and the next open creates a fresh attempt (a new random draw).
    """

    __tablename__ = "activity_attempts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_activity_attempts_tenant_id_id"),
        Index(
            "uq_activity_attempts_open",
            "tenant_id",
            "activity_id",
            "person_id",
            unique=True,
            postgresql_where=text("submitted_at IS NULL"),
        ),
        ForeignKeyConstraint(["tenant_id", "activity_id"], ["activities.tenant_id", "activities.id"],
                             ondelete="CASCADE", name="fk_activity_attempts_tenant_activity"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    activity_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    question_ext_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttemptGrant(Base, TimestampMixin):
    """Extra attempts given to one learner on one activity, and why.

    A grant is an *addition*, not an override: the effective limit is the
    activity's ``max_attempts`` plus the grants recorded here. Raising
    ``max_attempts`` would have re-opened the activity for every learner on it,
    and deleting the learner's submissions would have bought one retake by
    destroying the record of the attempts that motivated it — neither is a
    thing an administrator should have to do to grant a resit.

    Rows accumulate rather than being edited, so ``reason`` and ``granted_by``
    survive as the audit trail for an exam decision. There is no revoke: an
    attempt already granted may already have been sat, and withdrawing it after
    the fact would invalidate a result the learner was entitled to.
    """

    __tablename__ = "attempt_grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_attempt_grants_tenant_id_id"),
        Index("ix_attempt_grants_lookup", "tenant_id", "activity_id", "person_id"),
        ForeignKeyConstraint(["tenant_id", "activity_id"], ["activities.tenant_id", "activities.id"],
                             ondelete="CASCADE", name="fk_attempt_grants_tenant_activity"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    activity_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    extra_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    granted_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
