"""Scheduling service — cohort timetables of class sessions.

Repo convention: ``db`` + explicit ids, ``flush`` not ``commit``, domain
exceptions for the router to translate. RLS scopes reads to the tenant.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.class_session import SESSION_STATUSES, SESSION_TYPES, ClassSession
from app.models.cohort import Cohort
from app.services.exceptions import BadRequestError, NotFoundError

DELIVERY_MODES = frozenset({"self_paced", "live", "blended"})
_TYPES = frozenset(SESSION_TYPES)
_STATUSES = frozenset(SESSION_STATUSES)


def _cohort(db: Session, cohort_id: UUID) -> Cohort:
    cohort = db.get(Cohort, cohort_id)
    if cohort is None:
        raise NotFoundError("Cohort not found.")
    return cohort


def set_delivery_mode(db: Session, *, cohort_id: UUID, mode: str) -> Cohort:
    if mode not in DELIVERY_MODES:
        raise BadRequestError(f"Unknown delivery mode: {mode}")
    cohort = _cohort(db, cohort_id)
    cohort.delivery_mode = mode
    db.flush()
    return cohort


def create_session(
    db: Session,
    *,
    tenant_id: UUID,
    cohort_id: UUID,
    title: str,
    starts_at: datetime,
    session_type: str = "live_class",
    ends_at: datetime | None = None,
    offering_id: UUID | None = None,
    instructor_person_id: UUID | None = None,
    location: str | None = None,
    join_url: str | None = None,
    notes: str | None = None,
) -> ClassSession:
    if session_type not in _TYPES:
        raise BadRequestError(f"Unknown session type: {session_type}")
    if ends_at is not None and ends_at <= starts_at:
        raise BadRequestError("ends_at must be after starts_at.")
    cohort = _cohort(db, cohort_id)  # existence + RLS
    # Scheduling a session implies the cohort is not purely self-paced.
    if cohort.delivery_mode == "self_paced":
        cohort.delivery_mode = "blended"

    session = ClassSession(
        tenant_id=tenant_id,
        cohort_id=cohort_id,
        offering_id=offering_id,
        session_type=session_type,
        title=title.strip(),
        starts_at=starts_at,
        ends_at=ends_at,
        instructor_person_id=instructor_person_id,
        location=(location or None),
        join_url=(join_url or None),
        notes=(notes or None),
        status="scheduled",
    )
    db.add(session)
    db.flush()
    return session


def get_session(db: Session, *, session_id: UUID) -> ClassSession:
    session = db.get(ClassSession, session_id)
    if session is None:
        raise NotFoundError("Session not found.")
    return session


def list_for_cohort(
    db: Session, *, cohort_id: UUID, upcoming_only: bool = False, now: datetime | None = None
) -> list[ClassSession]:
    """The cohort's timetable, chronological."""
    stmt = select(ClassSession).where(ClassSession.cohort_id == cohort_id)
    if upcoming_only:
        stmt = stmt.where(
            ClassSession.status == "scheduled",
            ClassSession.starts_at > (now or datetime.now(tz=None).astimezone()),
        )
    return list(db.scalars(stmt.order_by(ClassSession.starts_at)).all())


def update_session(db: Session, *, session_id: UUID, **fields) -> ClassSession:
    session = get_session(db, session_id=session_id)
    allowed = {
        "title",
        "starts_at",
        "ends_at",
        "session_type",
        "offering_id",
        "instructor_person_id",
        "location",
        "join_url",
        "notes",
        "status",
    }
    for key, value in fields.items():
        if value is None or key not in allowed:
            continue
        if key == "session_type" and value not in _TYPES:
            raise BadRequestError(f"Unknown session type: {value}")
        if key == "status" and value not in _STATUSES:
            raise BadRequestError(f"Unknown status: {value}")
        setattr(session, key, value)
    if session.ends_at is not None and session.ends_at <= session.starts_at:
        raise BadRequestError("ends_at must be after starts_at.")
    db.flush()
    return session


def cancel_session(db: Session, *, session_id: UUID) -> ClassSession:
    session = get_session(db, session_id=session_id)
    session.status = "cancelled"
    db.flush()
    return session
