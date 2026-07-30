"""Scheduled CSV report builders (roadmap P3b, item 23).

Pure projections: every function renders canonical state (roster, completion,
work states, Success Queue) into a CSV string. Download routes and the weekly
outbox attachment both call these builders — one producer, two transports.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.person import Person
from app.models.success_queue import STATUS_RESOLVED, SuccessQueueEntry
from app.services import insights, learning_events, success_queue
from app.services.gradebook import course_grade

_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: object) -> object:
    """Neutralise CSV formula injection: a text cell starting with =, +, -, @,
    tab or CR is prefixed with a single quote so spreadsheet apps treat it as
    text, never a formula. Non-string cells pass through unchanged."""
    if isinstance(value, str) and value.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + value
    return value


def _csv(rows: list[list]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerows([sanitize_cell(c) for c in row] for row in rows)
    return buf.getvalue()


def _cohort(db: Session, tenant_id: UUID, cohort_id: UUID) -> Cohort:
    cohort = db.scalars(
        select(Cohort).where(Cohort.tenant_id == tenant_id).where(Cohort.id == cohort_id)
    ).first()
    if cohort is None:
        raise ValueError("cohort not found")
    return cohort


def cohort_roster_csv(db: Session, *, tenant_id: UUID, cohort_id: UUID,
                      now: datetime | None = None) -> tuple[str, str]:
    """Per-learner progress: completion, grade, last activity, open queue reasons."""
    now = now or datetime.now(UTC)
    cohort = _cohort(db, tenant_id, cohort_id)
    course_ids = insights._cohort_course_ids(db, tenant_id, cohort_id)

    people = db.scalars(
        select(Person)
        .join(Enrollment, (Enrollment.person_id == Person.id)
              & (Enrollment.tenant_id == Person.tenant_id))
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.role_in_cohort == "student")
        .where(Enrollment.status == "active")
        .order_by(Person.last_name, Person.first_name)
    ).all()

    rows: list[list] = [[
        "name", "email", "courses", "avg_completion_pct", "avg_grade_pct",
        "last_activity_at", "days_inactive", "open_queue_reasons",
    ]]
    for person in people:
        completions = db.scalars(
            select(CourseCompletion)
            .where(CourseCompletion.tenant_id == tenant_id)
            .where(CourseCompletion.person_id == person.id)
            .where(CourseCompletion.course_id.in_(course_ids or [cohort_id]))
        ).all()
        avg_completion = (
            round(100 * sum(c.pct for c in completions) / len(completions))
            if completions else 0
        )
        # Average over courses the learner has actually attempted (any graded
        # activity), not courses with pct>0 — a genuine 0% must count, and only
        # never-started courses should be excluded.
        grade_docs = [course_grade(db, tenant_id=tenant_id, person_id=person.id, course_id=cid)
                      for cid in course_ids]
        attempted_pcts = [
            g["pct"] for g in grade_docs
            if any(a["graded"] for a in g["per_activity"])
        ]
        avg_grade = round(sum(attempted_pcts) / len(attempted_pcts)) if attempted_pcts else 0
        last = learning_events.last_activity_at(db, tenant_id=tenant_id, person_id=person.id)
        reasons = list(db.scalars(
            select(SuccessQueueEntry.reason_kind)
            .where(SuccessQueueEntry.tenant_id == tenant_id)
            .where(SuccessQueueEntry.person_id == person.id)
            .where(SuccessQueueEntry.status != STATUS_RESOLVED)
        ).all())
        rows.append([
            f"{person.first_name} {person.last_name}".strip(), person.email,
            len(course_ids), avg_completion, avg_grade,
            last.isoformat() if last else "",
            (now - last).days if last else "",
            ";".join(sorted(reasons)),
        ])
    safe = cohort.name.lower().replace(" ", "-")[:40]
    return f"roster-progress-{safe}.csv", _csv(rows)


def cohort_funnel_csv(db: Session, *, tenant_id: UUID, cohort_id: UUID,
                      now: datetime | None = None) -> tuple[str, str]:
    """Completion funnel + work states, straight from the insights projection."""
    cohort = _cohort(db, tenant_id, cohort_id)
    ov = insights.cohort_overview(db, tenant_id=tenant_id, cohort_id=cohort_id, now=now)
    funnel = ov["funnel"]
    rows = [
        ["metric", "value"],
        ["enrolled", funnel["enrolled"]],
        ["started", funnel["started"]],
        ["half_way", funnel["half"]],
        ["completed", funnel["completed"]],
        ["certified", funnel["certified"]],
        ["active_last_7d", ov["active"]],
        ["inactive", ov["inactive"]],
        ["submitted_activities", ov["submitted"]],
        ["overdue_activities", ov["overdue"]],
        ["not_attempted_activities", ov["not_attempted"]],
        ["avg_score_pct", ov["avg_score_pct"] if ov["avg_score_pct"] is not None else ""],
        ["events_this_week", ov["week_events"]],
        ["events_prior_4wk_avg", ov["prior_week_avg"]],
    ]
    safe = cohort.name.lower().replace(" ", "-")[:40]
    return f"funnel-{safe}.csv", _csv(rows)


def queue_summary_csv(db: Session, *, tenant_id: UUID,
                      cohort_id: UUID | None = None) -> tuple[str, str]:
    """Open/acknowledged Success Queue entries, most severe first."""
    q = (
        select(SuccessQueueEntry, Person, Cohort.name)
        .join(Person, (Person.id == SuccessQueueEntry.person_id)
              & (Person.tenant_id == SuccessQueueEntry.tenant_id))
        .join(Cohort, (Cohort.id == SuccessQueueEntry.cohort_id)
              & (Cohort.tenant_id == SuccessQueueEntry.tenant_id), isouter=True)
        .where(SuccessQueueEntry.tenant_id == tenant_id)
        .where(SuccessQueueEntry.status != STATUS_RESOLVED)
        .order_by(success_queue.severity_order(), SuccessQueueEntry.detected_at.desc())
    )
    if cohort_id is not None:
        q = q.where(SuccessQueueEntry.cohort_id == cohort_id)
    rows: list[list] = [[
        "name", "email", "cohort", "reason", "severity", "status",
        "detected_at", "recommended_action", "facts",
    ]]
    for entry, person, cohort_name in db.execute(q).all():
        rows.append([
            f"{person.first_name} {person.last_name}".strip(), person.email,
            cohort_name or "", entry.reason_kind, entry.severity, entry.status,
            entry.detected_at.isoformat(), entry.recommended_action,
            ";".join(f"{k}={v}" for k, v in sorted(entry.supporting_facts.items())),
        ])
    return "success-queue.csv", _csv(rows)


def academy_summary_csv(db: Session, *, tenant_id: UUID,
                        now: datetime | None = None) -> tuple[str, str]:
    """Academy-level comparison: one row per cohort."""
    comparison = insights.cohorts_comparison(db, tenant_id=tenant_id, now=now)
    rows: list[list] = [[
        "cohort", "learners", "active_last_7d", "completed", "completion_pct",
    ]]
    for row in comparison:
        rows.append([
            row["cohort"].name, row["learners"], row["active"],
            row["completed"], row["completion_pct"],
        ])
    return "academy-summary.csv", _csv(rows)


def weekly_report_attachments(db: Session, *, tenant_id: UUID,
                              cohort_id: UUID) -> list[tuple[str, bytes, str]]:
    """The weekly instructor email's attachments, built at delivery time."""
    out: list[tuple[str, bytes, str]] = []
    for name, text in (
        cohort_roster_csv(db, tenant_id=tenant_id, cohort_id=cohort_id),
        cohort_funnel_csv(db, tenant_id=tenant_id, cohort_id=cohort_id),
        queue_summary_csv(db, tenant_id=tenant_id, cohort_id=cohort_id),
    ):
        out.append((name, text.encode("utf-8"), "text/csv"))
    # Guard: a report window with zero learners still yields valid header-only CSVs.
    if not out:  # pragma: no cover - construction above is static
        raise ValueError("no report attachments produced")
    return out


def week_key(now: datetime | None = None) -> str:
    """Stable idempotency component: ISO year-week of the send."""
    now = now or datetime.now(UTC)
    year, week, _ = (now - timedelta(hours=0)).isocalendar()
    return f"{year}W{week:02d}"
