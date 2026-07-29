"""iCalendar feed — hand-rolled RFC 5545 output plus feed-token management.

The feed is a read-only projection of the To-Do timeline (sessions +
deadlines). Auth is a single-purpose, long-lived AccountToken of kind
``ical_feed`` — multi-use by design (calendar apps poll), rotated by minting
a replacement, and never the session cookie (roadmap P1 item 10).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.account_token import AccountToken
from app.services.security import hash_token
from app.services.todo import timeline_for_person

ICAL_TOKEN_KIND = "ical_feed"  # noqa: S105 — token *kind* label, not a secret
ICAL_TOKEN_TTL_DAYS = 365


def mint_feed_token(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> str:
    """Create (or rotate) the person's feed token; returns the raw value once.

    Rotation = expire every previous ical_feed token so exactly one works.
    """
    now = now or datetime.now(UTC)
    old = db.scalars(
        select(AccountToken)
        .where(AccountToken.tenant_id == tenant_id)
        .where(AccountToken.person_id == person_id)
        .where(AccountToken.kind == ICAL_TOKEN_KIND)
    ).all()
    for t in old:
        t.expires_at = now
    raw = uuid4().hex + uuid4().hex
    db.add(
        AccountToken(
            tenant_id=tenant_id,
            person_id=person_id,
            kind=ICAL_TOKEN_KIND,
            token_hash=hash_token(raw),
            expires_at=now + timedelta(days=ICAL_TOKEN_TTL_DAYS),
        )
    )
    db.flush()
    return raw


def has_feed_token(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    return (
        db.scalars(
            select(AccountToken)
            .where(AccountToken.tenant_id == tenant_id)
            .where(AccountToken.person_id == person_id)
            .where(AccountToken.kind == ICAL_TOKEN_KIND)
            .where(AccountToken.expires_at > now)
        ).first()
        is not None
    )


def resolve_feed_token(db: Session, *, tenant_id: UUID, raw: str, now: datetime | None = None) -> UUID | None:
    """Return the person_id for a valid feed token, else None. Multi-use."""
    if not raw:
        return None
    now = now or datetime.now(UTC)
    token = db.scalars(
        select(AccountToken)
        .where(AccountToken.tenant_id == tenant_id)
        .where(AccountToken.kind == ICAL_TOKEN_KIND)
        .where(AccountToken.token_hash == hash_token(raw))
        .where(AccountToken.expires_at > now)
    ).first()
    return token.person_id if token else None


# --- RFC 5545 rendering -----------------------------------------------------


def _esc(value: str) -> str:
    return (
        (value or "")
        .replace("\\", "\\\\")
        .replace(";", "\\;")
        .replace(",", "\\,")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
    )


def _stamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def render_feed(events: list[dict], *, calname: str, now: datetime) -> str:
    """Render VCALENDAR text (CRLF line endings) from event dicts.

    Event dict: uid, summary, starts_at, ends_at (optional), description
    (optional), location (optional), url (optional).
    """
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Dotmac Academy//Learning Calendar//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{_esc(calname)}",
    ]
    for e in events:
        start = e["starts_at"]
        end = e.get("ends_at") or start
        lines += [
            "BEGIN:VEVENT",
            f"UID:{_esc(e['uid'])}",
            f"DTSTAMP:{_stamp(now)}",
            f"DTSTART:{_stamp(start)}",
            f"DTEND:{_stamp(end)}",
            f"SUMMARY:{_esc(e['summary'])}",
        ]
        if e.get("description"):
            lines.append(f"DESCRIPTION:{_esc(e['description'])}")
        if e.get("location"):
            lines.append(f"LOCATION:{_esc(e['location'])}")
        if e.get("url"):
            lines.append(f"URL:{_esc(e['url'])}")
        lines.append("END:VEVENT")
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


def events_for_person(db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime) -> list[dict]:
    """Flatten the To-Do projection into feed events (sessions + deadlines)."""
    t = timeline_for_person(db, tenant_id=tenant_id, person_id=person_id, now=now)
    events: list[dict] = []
    for s, cohort_name in t["sessions"]:
        events.append(
            {
                "uid": f"session-{s.id}@academy.dotmac.io",
                "summary": s.title,
                "starts_at": s.starts_at,
                "ends_at": s.ends_at,
                "description": f"{cohort_name} — live session" if s.session_type == "live_class" else cohort_name,
                "location": s.location or "",
                "url": s.join_url or "",
            }
        )
    for bucket in ("overdue", "due_today", "next_7", "next_30"):
        for row in t[bucket]:
            act = row["activity"]
            events.append(
                {
                    "uid": f"due-{act.id}@academy.dotmac.io",
                    "summary": f"Due: {act.title}",
                    "starts_at": row["due_at"],
                    "description": row["course_title"],
                }
            )
    return events
