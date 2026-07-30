"""Student reminder policy — the single owner of reminder decisions.

``sweep`` is a deterministic, idempotent pass over canonical state: it decides
which reminder occurrences exist right now, records each exactly once in the
``ReminderLog`` ledger, raises an in-app notification, and hands email
consequences to the transactional outbox (never SMTP directly). Frequency
modes, quiet hours, and per-event opt-outs are applied here and nowhere else.
Adapters (CLI, timer, web routes) stay thin; a future transport (WhatsApp/SMS)
plugs in as another delivery channel behind the same decisions.

Channel policy: an opt-out for an event kind suppresses BOTH channels.
Frequency and quiet hours pace the EMAIL channel only — in-app notifications
land at detection time (they are the passive record).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta
from html import escape
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.assessment import Activity, Score, Submission
from app.models.certificate import Certificate
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.reminder import (
    EVENT_KINDS,
    STATUS_QUEUED,
    STATUS_SENT,
    STATUS_SKIPPED,
    ReminderLog,
    ReminderPreference,
)
from app.services import learning_events, notifications
from app.services import todo as todo_service
from app.services.audit import write_audit_event
from app.services.email_outbox import enqueue_email
from app.services.localtime import academy_zone
from app.services.scheduling import list_for_person
from app.services.settings_store import effective

logger = logging.getLogger(__name__)

# Detection lookback for point-in-time events (new enrollment, grade, etc.).
# Wider than the sweep interval so a missed run never loses an occurrence;
# the ledger's uniqueness makes the overlap harmless.
POINT_EVENT_LOOKBACK_HOURS = 48

FREQUENCIES = ("immediate", "daily_digest", "weekly_digest")

_TITLES = {
    "course_assigned": "You've been enrolled",
    "course_starting": "A course opens soon",
    "due_72h": "Due in 3 days",
    "due_24h": "Due tomorrow",
    "overdue": "Overdue work",
    "session_24h": "Live session tomorrow",
    "session_1h": "Live session starting soon",
    "inactivity": "Pick up where you left off",
    "graded": "Your work has been graded",
    "course_completed": "Course completed",
    "certificate_issued": "Your certificate is ready",
}


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------


def get_preference(db: Session, *, tenant_id: UUID, person_id: UUID) -> ReminderPreference:
    """The person's preference row, created with defaults on first touch."""
    pref = db.scalars(
        select(ReminderPreference)
        .where(ReminderPreference.tenant_id == tenant_id)
        .where(ReminderPreference.person_id == person_id)
    ).first()
    if pref is None:
        pref = ReminderPreference(tenant_id=tenant_id, person_id=person_id, optouts=[])
        db.add(pref)
        db.flush()
    return pref


def save_preference(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    frequency: str,
    quiet_start_hour: int | None,
    quiet_end_hour: int | None,
    optouts: list[str],
) -> ReminderPreference:
    if frequency not in FREQUENCIES:
        frequency = "immediate"
    for h in (quiet_start_hour, quiet_end_hour):
        if h is not None and not 0 <= h <= 23:
            raise ValueError("quiet hours must be within 0..23")
    pref = get_preference(db, tenant_id=tenant_id, person_id=person_id)
    pref.frequency = frequency
    pref.quiet_start_hour = quiet_start_hour
    pref.quiet_end_hour = quiet_end_hour
    pref.optouts = [k for k in optouts if k in EVENT_KINDS]
    db.flush()
    return pref


def _in_quiet_hours(pref: ReminderPreference, now: datetime) -> bool:
    if pref.quiet_start_hour is None or pref.quiet_end_hour is None:
        return False
    hour = now.astimezone(academy_zone()).hour
    start, end = pref.quiet_start_hour, pref.quiet_end_hour
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # window crosses midnight


def _digest_due(pref: ReminderPreference, now: datetime, *, hour: int, weekday: int) -> bool:
    local = now.astimezone(academy_zone())
    if pref.frequency == "daily_digest":
        return local.hour == hour
    if pref.frequency == "weekly_digest":
        return local.weekday() == weekday and local.hour == hour
    return False


# ---------------------------------------------------------------------------
# Event detection (per person, from canonical state only)
# ---------------------------------------------------------------------------


def _detect_events(
    db: Session, *, tenant_id: UUID, person_id: UUID, now: datetime, inactivity_days: int
) -> list[dict]:
    """Every reminder occurrence that exists for this person right now."""
    events: list[dict] = []
    lookback = now - timedelta(hours=POINT_EVENT_LOOKBACK_HOURS)

    # New enrollments -> course_assigned.
    rows = db.execute(
        select(Enrollment.id, Cohort.name)
        .join(Cohort, (Cohort.id == Enrollment.cohort_id) & (Cohort.tenant_id == Enrollment.tenant_id))
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .where(Enrollment.created_at >= lookback)
    ).all()
    for enr_id, cohort_name in rows:
        events.append({
            "kind": "course_assigned",
            "key": f"course_assigned:{enr_id}",
            "title": f"You've been enrolled: {cohort_name}",
            "link": "/courses",
        })

    # Offerings opening within 72h -> course_starting.
    offering_rows = db.execute(
        select(CourseOffering.id, Course.title, CourseOffering.starts_at)
        .join(Course, (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id))
        .join(Enrollment, (Enrollment.cohort_id == CourseOffering.cohort_id)
              & (Enrollment.tenant_id == CourseOffering.tenant_id))
        .where(CourseOffering.tenant_id == tenant_id)
        .where(Enrollment.person_id == person_id)
        .where(Enrollment.status == "active")
        .where(CourseOffering.status == "active")
        .where(CourseOffering.starts_at.is_not(None))
        .where(CourseOffering.starts_at > now)
        .where(CourseOffering.starts_at <= now + timedelta(hours=72))
    ).all()
    for off_id, course_title, _starts in offering_rows:
        events.append({
            "kind": "course_starting",
            "key": f"course_starting:{off_id}",
            "title": f"Course opening soon: {course_title}",
            "link": "/courses",
        })

    # Deadlines -> due_72h / due_24h / overdue (reuses the To-Do derivation).
    for row in todo_service._deadline_rows(db, tenant_id=tenant_id, person_id=person_id):
        due, activity = row["due_at"], row["activity"]
        link = "/todo"
        if due < now:
            events.append({
                "kind": "overdue",
                "key": f"overdue:{activity.id}:{due.date().isoformat()}",
                "title": f"Overdue: {activity.title} ({row['course_title']})",
                "link": link,
            })
        elif due <= now + timedelta(hours=24):
            events.append({
                "kind": "due_24h",
                "key": f"due_24h:{activity.id}:{due.date().isoformat()}",
                "title": f"Due tomorrow: {activity.title} ({row['course_title']})",
                "link": link,
            })
        elif due <= now + timedelta(hours=72):
            events.append({
                "kind": "due_72h",
                "key": f"due_72h:{activity.id}:{due.date().isoformat()}",
                "title": f"Due in 3 days: {activity.title} ({row['course_title']})",
                "link": link,
            })

    # Live sessions -> session_24h / session_1h. The occurrence key is versioned
    # by the scheduled start time, so rescheduling a session issues a FRESH
    # reminder (the old key stays consumed for the old time); a same-schedule
    # re-sweep still dedupes. Opt-out suppression is unchanged and intentional.
    upcoming = list_for_person(db, tenant_id=tenant_id, person_id=person_id, now=now)["upcoming"]
    for session, _cohort_name in upcoming:
        delta = session.starts_at - now
        link = f"/timetable/sessions/{session.id}"
        sched = session.starts_at.astimezone(UTC).strftime("%Y%m%dT%H%M")
        if timedelta(0) < delta <= timedelta(hours=1):
            events.append({
                "kind": "session_1h",
                "key": f"session_1h:{session.id}:{sched}",
                "title": f"Starting soon: {session.title}",
                "link": link,
            })
        elif timedelta(0) < delta <= timedelta(hours=24):
            events.append({
                "kind": "session_24h",
                "key": f"session_24h:{session.id}:{sched}",
                "title": f"Tomorrow: {session.title}",
                "link": link,
            })

    # Grades -> graded. Only non-auto scores: auto-graded quiz results are shown
    # on screen the instant the learner submits, so emailing them is pure noise
    # (one message per practice attempt). Manual/override grading is the news.
    rows = db.execute(
        select(Score.id, Activity.title)
        .join(Submission, (Submission.id == Score.submission_id) & (Submission.tenant_id == Score.tenant_id))
        .join(Activity, (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id))
        .where(Score.tenant_id == tenant_id)
        .where(Submission.person_id == person_id)
        .where(Score.source != "auto")
        .where(Score.created_at >= lookback)
    ).all()
    for score_id, activity_title in rows:
        events.append({
            "kind": "graded",
            "key": f"graded:{score_id}",
            "title": f"Graded: {activity_title}",
            "link": "/progress",
        })

    # Completions -> course_completed.
    rows = db.execute(
        select(CourseCompletion.id, Course.title)
        .join(Course, (Course.id == CourseCompletion.course_id) & (Course.tenant_id == CourseCompletion.tenant_id))
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.status == "completed")
        .where(CourseCompletion.completed_at.is_not(None))
        .where(CourseCompletion.completed_at >= lookback)
    ).all()
    for comp_id, course_title in rows:
        events.append({
            "kind": "course_completed",
            "key": f"course_completed:{comp_id}",
            "title": f"Completed: {course_title}",
            "link": "/progress",
        })

    # Certificates -> certificate_issued. (The Certificate model has no expiry
    # field, so certificate-expiry reminders are out of scope until it does.)
    rows = db.execute(
        select(Certificate.id, Course.title)
        .join(Course, (Course.id == Certificate.course_id) & (Course.tenant_id == Certificate.tenant_id))
        .where(Certificate.tenant_id == tenant_id)
        .where(Certificate.person_id == person_id)
        .where(Certificate.issued_at >= lookback)
    ).all()
    for cert_id, course_title in rows:
        events.append({
            "kind": "certificate_issued",
            "key": f"certificate_issued:{cert_id}",
            "title": f"Certificate ready: {course_title}",
            "link": "/progress",
        })

    # Inactivity -> one reminder per inactive spell. The learning-event ledger
    # is the canonical record of meaningful activity (chapter views, opened
    # attempts, submissions, lab launches, ...), so use it rather than a partial
    # ChapterRead/Submission pair. A learner who enrolled but never did anything
    # has no ledger row at all; anchor them on their earliest active enrolment so
    # the never-started case — the one most needing a nudge — still fires.
    last_touch = learning_events.last_activity_at(db, tenant_id=tenant_id, person_id=person_id)
    anchor = last_touch
    if anchor is None:
        anchor = db.scalar(
            select(func.min(Enrollment.created_at))
            .where(Enrollment.tenant_id == tenant_id)
            .where(Enrollment.person_id == person_id)
            .where(Enrollment.status == "active")
        )
    if anchor is not None and anchor < now - timedelta(days=inactivity_days):
        never_started = last_touch is None
        events.append({
            "kind": "inactivity",
            "key": f"inactivity:{anchor.date().isoformat()}",
            "title": (
                "Ready to begin? Your course is waiting"
                if never_started
                else "It's been a while — pick up where you left off"
            ),
            "link": "/",
        })

    return events


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------


def _record(db: Session, *, tenant_id: UUID, person_id: UUID, event: dict,
            channel: str, status: str, outbox_key: str | None, now: datetime) -> bool:
    """Insert the ledger row; False when this occurrence was already handled."""
    result = db.execute(
        insert(ReminderLog)
        .values(
            tenant_id=tenant_id,
            person_id=person_id,
            event_kind=event["kind"],
            occurrence_key=event["key"][:160],
            title=event["title"][:240],
            link=event.get("link"),
            channel=channel,
            status=status,
            outbox_key=outbox_key,
            sent_at=now if status == STATUS_SENT else None,
        )
        .on_conflict_do_nothing(constraint="uq_reminder_log_occurrence")
        .returning(ReminderLog.id)
    ).first()
    db.flush()
    return result is not None


def _email_for(event_title: str, link: str | None, branding: str, base_url: str) -> tuple[str, str, str]:
    subject = f"{event_title} — {branding}"
    url = f"{base_url}{link}" if link and link.startswith("/") else (link or "")
    # Titles carry staff-authored activity/course/session names; escape before
    # interpolating into email HTML.
    safe_title = escape(event_title)
    html = (
        f"<p>{safe_title}.</p>"
        + (f'<p><a href="{escape(url)}">Open the academy</a></p>' if url else "")
        + f"<p>— {escape(branding)}</p>"
    )
    text = f"{event_title}.\n{url}\n— {branding}"
    return subject, html, text


def sweep(db: Session, *, tenant_id: UUID, now: datetime | None = None) -> dict:
    """One deterministic pass: detect, ledger, notify, enqueue, flush digests."""
    now = now or datetime.now(UTC)
    cfg = effective(db)
    if not bool(cfg.get("reminders_enabled", True)):
        return {"detected": 0, "sent": 0, "queued": 0, "skipped": 0, "flushed": 0, "disabled": True}
    inactivity_days = int(str(cfg.get("reminder_inactivity_days", 7)))
    digest_hour = int(str(cfg.get("reminder_digest_hour", 7)))
    digest_weekday = int(str(cfg.get("reminder_digest_weekday", 0)))
    branding = str(cfg.get("branding_name", "Dotmac Academy"))
    base_url = str(cfg.get("academy_base_url", "https://academy.dotmac.io")).rstrip("/")

    # Student reminders are for students: an instructor enrolment must not draw
    # due-date nags or inactivity chides for coursework that isn't theirs.
    person_rows = db.execute(
        select(Person)
        .join(Enrollment, (Enrollment.person_id == Person.id) & (Enrollment.tenant_id == Person.tenant_id))
        .where(Person.tenant_id == tenant_id)
        .where(Person.status == "active")
        .where(Enrollment.status == "active")
        .where(Enrollment.role_in_cohort == "student")
        .distinct()
    ).scalars().all()

    counts = {"detected": 0, "sent": 0, "queued": 0, "skipped": 0, "flushed": 0}

    for person in person_rows:
        pref = get_preference(db, tenant_id=tenant_id, person_id=person.id)
        optouts = set(pref.optouts or [])
        events = _detect_events(db, tenant_id=tenant_id, person_id=person.id,
                                now=now, inactivity_days=inactivity_days)

        for event in events:
            if event["kind"] in optouts:
                if _record(db, tenant_id=tenant_id, person_id=person.id, event=event,
                           channel="none", status=STATUS_SKIPPED, outbox_key=None, now=now):
                    counts["detected"] += 1
                    counts["skipped"] += 1
                continue

            send_now = pref.frequency == "immediate" and not _in_quiet_hours(pref, now)
            if send_now:
                outbox_key = f"reminder:{event['key']}:{person.id}"[:200]
                # _record is the idempotency guard: it succeeds only for a
                # genuinely new occurrence, which therefore has a fresh, unique
                # outbox key — so the enqueue below cannot collide, and the
                # recorded "sent" status is truthful (unlike the digest path,
                # where batches can recur and the key is content-hashed).
                if _record(db, tenant_id=tenant_id, person_id=person.id, event=event,
                           channel="email", status=STATUS_SENT, outbox_key=outbox_key, now=now):
                    counts["detected"] += 1
                    counts["sent"] += 1
                    subject, html, text = _email_for(event["title"], event.get("link"), branding, base_url)
                    enqueue_email(db, tenant_id=tenant_id, idempotency_key=outbox_key,
                                  kind=f"reminder_{event['kind']}", recipient=person.email,
                                  subject=subject, html_body=html, text_body=text)
                    notifications.notify(db, tenant_id=tenant_id, person_id=person.id,
                                         kind="reminder", title=event["title"], link=event.get("link"))
            else:
                if _record(db, tenant_id=tenant_id, person_id=person.id, event=event,
                           channel="email", status=STATUS_QUEUED, outbox_key=None, now=now):
                    counts["detected"] += 1
                    counts["queued"] += 1
                    notifications.notify(db, tenant_id=tenant_id, person_id=person.id,
                                         kind="reminder", title=event["title"], link=event.get("link"))

        # Flush queued rows: digest boundary, or deferred-immediate leaving quiet hours.
        flush = (
            _digest_due(pref, now, hour=digest_hour, weekday=digest_weekday)
            or (pref.frequency == "immediate" and not _in_quiet_hours(pref, now))
        )
        if flush:
            counts["flushed"] += _flush_queued(
                db, tenant_id=tenant_id, person=person, branding=branding,
                base_url=base_url, now=now,
            )

    return counts


def _flush_queued(db: Session, *, tenant_id: UUID, person: Person, branding: str,
                  base_url: str, now: datetime) -> int:
    queued = db.scalars(
        select(ReminderLog)
        .where(ReminderLog.tenant_id == tenant_id)
        .where(ReminderLog.person_id == person.id)
        .where(ReminderLog.status == STATUS_QUEUED)
        .order_by(ReminderLog.created_at)
    ).all()
    if not queued:
        return 0
    # Key on the batch contents, not just the hour: the timer sweeps every few
    # minutes, so two flushes can land in the same hour. An hour-granular key
    # made the second digest collide on the outbox's idempotency guard — the
    # email was silently dropped while these rows were still marked sent. The
    # content hash gives each distinct batch its own email; only mark rows sent
    # when the enqueue actually took.
    digest_disc = hashlib.sha1(
        ",".join(str(r.id) for r in queued).encode(), usedforsecurity=False
    ).hexdigest()[:12]
    outbox_key = f"reminder_digest:{person.id}:{digest_disc}"
    items_html = "".join(f"<li>{escape(r.title)}</li>" for r in queued)
    items_text = "\n".join(f"- {r.title}" for r in queued)
    enqueued = enqueue_email(
        db, tenant_id=tenant_id, idempotency_key=outbox_key, kind="reminder_digest",
        recipient=person.email,
        subject=f"Your learning reminders ({len(queued)}) — {branding}",
        html_body=f"<p>While you were away:</p><ul>{items_html}</ul>"
                  f'<p><a href="{base_url}/todo">Open your To-Do list</a></p>'
                  f"<p>— {branding}</p>",
        text_body=f"While you were away:\n{items_text}\n— {branding}",
    )
    if not enqueued:
        # Identical batch already enqueued (true idempotent retry): those rows
        # are already in a delivered digest, so marking them sent is correct.
        pass
    for r in queued:
        r.status = STATUS_SENT
        r.outbox_key = outbox_key
        r.sent_at = now
    db.flush()
    return len(queued)


# ---------------------------------------------------------------------------
# History + resend (admin)
# ---------------------------------------------------------------------------


def recent_log(db: Session, *, tenant_id: UUID, limit: int = 100, offset: int = 0) -> list:
    """Recent ledger rows joined with the person for the admin history page."""
    return list(db.execute(
        select(ReminderLog, Person)
        .join(Person, (Person.id == ReminderLog.person_id) & (Person.tenant_id == ReminderLog.tenant_id))
        .where(ReminderLog.tenant_id == tenant_id)
        .order_by(ReminderLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all())


def resend(db: Session, *, tenant_id: UUID, log_id: UUID, actor_person_id: UUID) -> ReminderLog:
    """Authorized re-delivery of one ledger entry through a fresh outbox row."""
    log = db.scalars(
        select(ReminderLog)
        .where(ReminderLog.tenant_id == tenant_id)
        .where(ReminderLog.id == log_id)
    ).first()
    if log is None:
        raise ValueError("reminder not found")
    person = db.scalars(
        select(Person).where(Person.tenant_id == tenant_id).where(Person.id == log.person_id)
    ).first()
    if person is None:
        raise ValueError("person not found")
    cfg = effective(db)
    branding = str(cfg.get("branding_name", "Dotmac Academy"))
    base_url = str(cfg.get("academy_base_url", "https://academy.dotmac.io")).rstrip("/")
    outbox_key = f"reminder_resend:{log.id}:{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    subject, html, text = _email_for(log.title, log.link, branding, base_url)
    enqueue_email(db, tenant_id=tenant_id, idempotency_key=outbox_key,
                  kind=f"reminder_{log.event_kind}", recipient=person.email,
                  subject=subject, html_body=html, text_body=text)
    log.status = STATUS_SENT
    log.outbox_key = outbox_key
    log.sent_at = datetime.now(UTC)
    write_audit_event(db, tenant_id=tenant_id, actor_person_id=actor_person_id,
                      action="reminder.resend", entity_type="reminder_log",
                      entity_id=str(log.id), details={"event_kind": log.event_kind})
    db.flush()
    return log
