from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, ForeignKeyConstraint, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class Track(Base, TimestampMixin):
    """Reusable curriculum path made up of ordered courses."""

    __tablename__ = "tracks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "slug", name="uq_tracks_tenant_slug"),
        UniqueConstraint("tenant_id", "id", name="uq_tracks_tenant_id_id"),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class TrackCourse(Base, TimestampMixin):
    """Ordered course membership for a track."""

    __tablename__ = "track_courses"
    __table_args__ = (
        UniqueConstraint("tenant_id", "track_id", "course_id", name="uq_track_courses_track_course"),
        ForeignKeyConstraint(
            ["tenant_id", "track_id"],
            ["tracks.tenant_id", "tracks.id"],
            ondelete="CASCADE",
            name="fk_track_courses_tenant_track",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "course_id"],
            ["courses.tenant_id", "courses.id"],
            ondelete="CASCADE",
            name="fk_track_courses_tenant_course",
        ),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    track_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    course_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class CohortTrack(Base, TimestampMixin):
    """A track enabled for a cohort."""

    __tablename__ = "cohort_tracks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_cohort_tracks_tenant_id_id"),
        UniqueConstraint("tenant_id", "cohort_id", "track_id", name="uq_cohort_tracks_cohort_track"),
        ForeignKeyConstraint(
            ["tenant_id", "cohort_id"],
            ["cohorts.tenant_id", "cohorts.id"],
            ondelete="CASCADE",
            name="fk_cohort_tracks_tenant_cohort",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "track_id"],
            ["tracks.tenant_id", "tracks.id"],
            ondelete="CASCADE",
            name="fk_cohort_tracks_tenant_track",
        ),
    )
    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cohort_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    track_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
