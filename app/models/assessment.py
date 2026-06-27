from __future__ import annotations
from uuid import UUID
from sqlalchemy import Boolean, Float, ForeignKey, ForeignKeyConstraint, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, TimestampMixin, uuid_pk


def _tenant_fk():
    return mapped_column(PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
                         nullable=False, index=True)


class QuestionBank(Base, TimestampMixin):
    __tablename__ = "question_banks"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_question_banks_tenant_id_id"),)
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    chapter_number: Mapped[int | None] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # chapter|mid|final
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class Question(Base, TimestampMixin):
    __tablename__ = "questions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "bank_id", "ext_id", name="uq_questions_bank_ext"),
        ForeignKeyConstraint(["tenant_id", "bank_id"], ["question_banks.tenant_id", "question_banks.id"],
                             ondelete="CASCADE", name="fk_questions_tenant_bank"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    bank_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    ext_id: Mapped[str] = mapped_column(String(60), nullable=False)
    stem: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(12), nullable=False)  # single|multi|truefalse
    options: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    correct: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    rubric_category: Mapped[str] = mapped_column(String(12), nullable=False)  # recall|application|analysis
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class Activity(Base, TimestampMixin):
    __tablename__ = "activities"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_activities_tenant_id_id"),)
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    chapter_number: Mapped[int | None] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(16), nullable=False, default="mcq_test")
    bank_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    pass_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Assessment policy (Slice 4). Null = unlimited attempts.
    max_attempts: Mapped[int | None] = mapped_column(Integer)


class Submission(Base, TimestampMixin):
    __tablename__ = "submissions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_submissions_tenant_id_id"),
        ForeignKeyConstraint(["tenant_id", "activity_id"], ["activities.tenant_id", "activities.id"],
                             ondelete="CASCADE", name="fk_submissions_tenant_activity"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    activity_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    person_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    answers: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class Score(Base, TimestampMixin):
    __tablename__ = "scores"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "submission_id"], ["submissions.tenant_id", "submissions.id"],
                             ondelete="CASCADE", name="fk_scores_tenant_submission"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = _tenant_fk()
    submission_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    max_score: Mapped[float] = mapped_column(Float, nullable=False)
    fraction: Mapped[float] = mapped_column(Float, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    per_item: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    source: Mapped[str] = mapped_column(String(10), nullable=False, default="auto")
    override_reason: Mapped[str | None] = mapped_column(Text)
