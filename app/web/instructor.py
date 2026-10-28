# app/web/instructor.py
"""Instructor portal routes.

All routes are gated by require_web_role("instructor") — students and unauthenticated
users receive 403 or a redirect to /login respectively.

IMPORTANT: no db.commit() calls inside any handler. The get_db dependency manages the
transaction: it does SET LOCAL app.current_tenant (transaction-scoped) and commits
after the response is built. A mid-handler commit would clear that GUC and break RLS.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape
from typing import cast
from uuid import UUID

from dotmac_kernel.audit import resolve_event_attribution
from dotmac_kernel.models import Party, PartyPerson, PartyRoleGrant, PartyType, Role
from dotmac_learning import (
    AttemptAuditContext,
    BankLifecycleError,
    ChapterFact,
    authoring_chapters,
    get_activity,
    instructor_assigned_course_ids,
)
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.completion import CourseCompletion
from app.models.course import Chapter, Course
from app.models.identity_extensions import AcademyAccountProfile
from app.models.offering import CourseOffering
from app.services import announcements as ann_svc
from app.services import attempt_policy, learning_policy, scheduling
from app.services import bank_authoring as _banks
from app.services import tracks as track_svc
from app.services.analytics import item_analysis
from app.services.assessment import override_score, pending_grading
from app.services.authoring import create_course, delete_chapter, editable_chapter_source, upsert_chapter
from app.services.canonical_lifecycle import set_account_status
from app.services.dashboards import cohort_overview
from app.services.email_outbox import enqueue_email
from app.services.exceptions import BadRequestError, NotFoundError
from app.services.identity import AcademyCurrentAccount
from app.services.invitation_issuance import cohort_fact, invite_web_cohort_account, track_fact
from app.services.localtime import local_to_utc
from app.services.lookups import cohort_or_404
from app.services.product_admin_access import (
    require_bank_author_access,
    require_bank_export_access,
    require_bank_publish_access,
    require_bank_repoint_access,
    require_bank_retire_access,
)
from app.services.roles import role_slugs
from app.services.roster import assign_facilitator, bulk_enroll, remove_facilitator, set_roster_state
from app.services.security import hash_token
from app.services.settings_store import effective
from app.services.web_auth import require_web_role, require_web_user
from app.web.pagination import pagination_context
from app.web.responses import hx_redirect
from app.web.templating import templates

router = APIRouter(
    prefix="/instructor",
    dependencies=[Depends(require_tenant), Depends(require_web_role("instructor"))],
)


def _e(value: object) -> str:
    """HTML-escape a value for safe interpolation into hand-built HTML responses.

    These instructor pages render learner-controlled data (names, emails, titles),
    so every interpolation must be escaped to prevent stored XSS across the
    student->instructor boundary.
    """
    return escape(str(value))


@dataclass(frozen=True, slots=True)
class _RosterPerson:
    """Purpose-specific roster display values; never request authority."""

    id: UUID
    email: str
    first_name: str
    last_name: str
    status: str


def _roster_statement():
    return (
        select(
            Enrollment,
            Party.id,
            Party.email,
            PartyPerson.first_name,
            PartyPerson.last_name,
            AcademyAccountProfile.status,
        )
        .select_from(Enrollment)
        .join(Party, (Party.id == Enrollment.person_id) & (Party.tenant_id == Enrollment.tenant_id))
        .join(PartyPerson, PartyPerson.party_id == Party.id)
        .join(
            AcademyAccountProfile,
            (AcademyAccountProfile.party_id == Party.id) & (AcademyAccountProfile.tenant_id == Party.tenant_id),
        )
        .where(Party.party_type == PartyType.person)
    )


def _roster_pairs(rows):
    return [(row[0], _RosterPerson(*row[1:])) for row in rows]


@router.get("/cohorts", response_class=HTMLResponse)
def cohorts_list(
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    is_admin = _is_admin(db, tenant.id, person.id)
    rows = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id).order_by(Cohort.name)).all()
    roster_rows = _roster_pairs(
        db.execute(
            _roster_statement()
            .where(Enrollment.tenant_id == tenant.id)
            .order_by(PartyPerson.last_name, PartyPerson.first_name, Party.email)
        ).all()
    )
    # Every enrollment is shown regardless of Enrollment.status, Enrollment.role_in_cohort
    # or Person.status (finding #3): a dropped/waitlisted student or a suspended account
    # must stay visible so an instructor can act on it, not disappear silently.
    roster_by_cohort: dict[UUID, list[dict]] = {cohort.id: [] for cohort in rows}
    active_student_counts: dict[UUID, int] = {cohort.id: 0 for cohort in rows}
    facilitators_by_cohort: dict[UUID, list[_RosterPerson]] = {cohort.id: [] for cohort in rows}
    for enrollment, student in roster_rows:
        if enrollment.cohort_id not in roster_by_cohort:
            continue
        is_active_student = (
            enrollment.status == "active" and enrollment.role_in_cohort == "student" and student.status == "active"
        )
        if is_active_student:
            active_student_counts[enrollment.cohort_id] += 1
        if enrollment.status == "active" and enrollment.role_in_cohort == "instructor":
            facilitators_by_cohort[enrollment.cohort_id].append(student)
        roster_by_cohort[enrollment.cohort_id].append({"enrollment": enrollment, "person": student})
    instructor_candidates = [
        _RosterPerson(*row)
        for row in db.execute(
            select(Party.id, Party.email, PartyPerson.first_name, PartyPerson.last_name, AcademyAccountProfile.status)
            .join(PartyPerson, PartyPerson.party_id == Party.id)
            .join(
                AcademyAccountProfile,
                (AcademyAccountProfile.party_id == Party.id) & (AcademyAccountProfile.tenant_id == Party.tenant_id),
            )
            .join(
                PartyRoleGrant,
                (PartyRoleGrant.party_id == Party.id) & (PartyRoleGrant.tenant_id == Party.tenant_id),
            )
            .join(Role, (Role.id == PartyRoleGrant.role_id) & (Role.tenant_id == PartyRoleGrant.tenant_id))
            .where(Party.tenant_id == tenant.id, Party.party_type == PartyType.person)
            .where(AcademyAccountProfile.status == "active")
            .where(Role.slug == "instructor")
            .order_by(PartyPerson.last_name, PartyPerson.first_name, Party.email)
        )
        .unique(lambda row: row.id)
        .all()
    ]
    tracks_by_cohort = {
        cohort.id: track_svc.list_cohort_tracks(db, tenant_id=tenant.id, cohort_id=cohort.id) for cohort in rows
    }
    # Draft courses are excluded from the ADD/CREATE checkbox lists (finding #2): a
    # draft is invisible to learners (see entitlements.py), so placing one in a track
    # would silently grant nothing. This does not touch a track's EXISTING membership
    # (list_cohort_tracks, above) — a draft already added keeps showing there.
    courses = list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tenant.id)
            .where(Course.status.in_(("published", "completed")))
            .order_by(Course.title)
        ).all()
    )
    draft_course_count = (
        db.scalar(
            select(func.count())
            .select_from(Course)
            .where(Course.tenant_id == tenant.id)
            .where(Course.status == "draft")
        )
        or 0
    )
    offering_rows = db.execute(
        select(CourseOffering.cohort_id, Course)
        .join(
            Course,
            (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id),
        )
        .where(CourseOffering.tenant_id == tenant.id)
        .where(CourseOffering.status == "active")
        .order_by(Course.title)
    ).all()
    courses_by_cohort: dict[UUID, list[Course]] = {cohort.id: [] for cohort in rows}
    seen_course_pairs: set[tuple[UUID, UUID]] = set()
    for cohort_id, course in offering_rows:
        key = (cohort_id, course.id)
        if cohort_id in courses_by_cohort and key not in seen_course_pairs:
            courses_by_cohort[cohort_id].append(course)
            seen_course_pairs.add(key)
    cohort_rows = [
        {
            "cohort": cohort,
            "roster": roster_by_cohort.get(cohort.id, []),
            "active_student_count": active_student_counts.get(cohort.id, 0),
            "facilitators": facilitators_by_cohort.get(cohort.id, []),
            "available_facilitators": [
                candidate
                for candidate in instructor_candidates
                if candidate.id not in {person.id for person in facilitators_by_cohort.get(cohort.id, [])}
            ],
            "tracks": tracks_by_cohort.get(cohort.id, []),
            "available_courses": courses,
        }
        for cohort in rows
    ]
    return templates.TemplateResponse(
        request,
        "instructor/cohorts.html",
        {
            "request": request,
            "cohorts": rows,
            "cohort_rows": cohort_rows,
            "courses": courses,
            "all_courses": courses,
            "draft_course_count": draft_course_count,
            "is_admin": is_admin,
        },
    )


@router.post("/cohorts")
def create_cohort(
    request: Request,
    name: str = Form(...),
    discipline: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    db.add(Cohort(tenant_id=tenant.id, name=name, discipline=discipline, status="active"))
    # No db.commit() here — get_db commits after the response is returned.
    return hx_redirect(request, "/instructor/cohorts")


def _split_emails(*fields: str) -> list[str]:
    """Split one or more textarea/CSV email fields into a flat list."""
    out: list[str] = []
    for f in fields:
        for chunk in (f or "").replace(",", "\n").replace(";", "\n").split():
            out.append(chunk)
    return out


def _is_admin(db: Session, tenant_id: UUID, person_id: UUID) -> bool:
    return "admin" in role_slugs(db, tenant_id, person_id)


def _cohort_action_target(cohort_id: UUID, return_to: str) -> str:
    """Allow membership actions to return only to a known cohort workspace."""
    workspace = f"/instructor/cohorts/{cohort_id}"
    return workspace if return_to == workspace else "/instructor/cohorts"


@router.get("/cohorts/{cohort_id}", response_class=HTMLResponse)
def cohort_detail(
    cohort_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(12, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Dedicated cohort workspace with roster progress and curriculum detail."""
    tenant = require_tenant(request)
    cohort = cohort_or_404(db, tenant_id=tenant.id, cohort_id=cohort_id)

    roster_pairs = _roster_pairs(
        db.execute(
            _roster_statement()
            .where(Enrollment.tenant_id == tenant.id)
            .where(Enrollment.cohort_id == cohort_id)
            .where(Enrollment.role_in_cohort == "student")
            .order_by(PartyPerson.last_name, PartyPerson.first_name, Party.email)
        ).all()
    )
    student_ids = [student.id for _, student in roster_pairs]

    offering_pairs = list(
        db.execute(
            select(CourseOffering, Course)
            .join(
                Course,
                (Course.id == CourseOffering.course_id) & (Course.tenant_id == CourseOffering.tenant_id),
            )
            .where(CourseOffering.tenant_id == tenant.id)
            .where(CourseOffering.cohort_id == cohort_id)
            .order_by(Course.title)
        ).all()
    )
    active_course_ids = [offering.course_id for offering, _ in offering_pairs if offering.status == "active"]

    completion_by_student: dict[UUID, dict[UUID, float]] = {}
    if student_ids and active_course_ids:
        for person_id, course_id, pct in db.execute(
            select(CourseCompletion.person_id, CourseCompletion.course_id, CourseCompletion.pct)
            .where(CourseCompletion.tenant_id == tenant.id)
            .where(CourseCompletion.person_id.in_(student_ids))
            .where(CourseCompletion.course_id.in_(active_course_ids))
        ).all():
            completion_by_student.setdefault(person_id, {})[course_id] = pct

    last_activity_by_student: dict[UUID, datetime] = {}
    if student_ids and active_course_ids:
        last_activity_by_student = {
            person_id: last_activity
            for person_id, last_activity in db.execute(
                select(Submission.person_id, func.max(Score.created_at))
                .join(
                    Score,
                    (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id),
                )
                .join(
                    Activity,
                    (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id),
                )
                .where(Submission.tenant_id == tenant.id)
                .where(Submission.person_id.in_(student_ids))
                .where(Activity.course_id.in_(active_course_ids))
                .group_by(Submission.person_id)
            ).all()
        }

    track_items = track_svc.list_cohort_tracks(db, tenant_id=tenant.id, cohort_id=cohort_id)
    track_names = {item["track"].id: item["track"].name for item in track_items}
    course_track_names: dict[UUID, list[str]] = {}
    for item in track_items:
        for course in item["courses"]:
            course_track_names.setdefault(course.id, []).append(item["track"].name)

    stale_before = datetime.now(UTC) - timedelta(days=14)
    student_rows_all: list[dict] = []
    for enrollment, student in roster_pairs:
        pcts = completion_by_student.get(student.id, {})
        completion_pct = (
            sum(pcts.get(course_id, 0.0) for course_id in active_course_ids) / len(active_course_ids)
            if active_course_ids
            else 0.0
        )
        last_activity_at = last_activity_by_student.get(student.id)
        is_current = enrollment.status == "active" and student.status == "active"
        student_rows_all.append(
            {
                "person": student,
                "enrollment": enrollment,
                "track_name": track_names.get(enrollment.track_id),
                "completion_pct": completion_pct,
                "last_activity_at": last_activity_at,
                "at_risk": is_current
                and completion_pct < 0.5
                and (last_activity_at is None or last_activity_at < stale_before),
            }
        )

    active_rows = [
        row for row in student_rows_all if row["enrollment"].status == "active" and row["person"].status == "active"
    ]
    at_risk_count = sum(1 for row in active_rows if row["at_risk"])
    average_progress = sum(row["completion_pct"] for row in active_rows) / len(active_rows) if active_rows else 0.0
    student_rows = student_rows_all[offset : offset + limit]

    facilitator_pairs = _roster_pairs(
        db.execute(
            _roster_statement()
            .where(Enrollment.tenant_id == tenant.id)
            .where(Enrollment.cohort_id == cohort_id)
            .where(Enrollment.role_in_cohort == "instructor")
            .where(Enrollment.status == "active")
            .order_by(PartyPerson.last_name, PartyPerson.first_name, Party.email)
        ).all()
    )

    offered_course_ids = [course.id for _, course in offering_pairs]
    chapters_by_course: dict[UUID, list[Chapter]] = {course_id: [] for course_id in offered_course_ids}
    activities_by_course: dict[UUID, list[Activity]] = {course_id: [] for course_id in offered_course_ids}
    if offered_course_ids:
        for chapter in db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id.in_(offered_course_ids))
            .order_by(Chapter.course_id, Chapter.order_index, Chapter.number)
        ).all():
            chapters_by_course.setdefault(chapter.course_id, []).append(chapter)
        for activity in db.scalars(
            select(Activity)
            .where(Activity.tenant_id == tenant.id)
            .where(Activity.course_id.in_(offered_course_ids))
            .order_by(Activity.course_id, Activity.chapter_number, Activity.title)
        ).all():
            activities_by_course.setdefault(activity.course_id, []).append(activity)

    course_rows: list[dict] = []
    for offering, course in offering_pairs:
        course_chapters = chapters_by_course.get(course.id, [])
        course_activities = activities_by_course.get(course.id, [])
        chapter_numbers = {chapter.number for chapter in course_chapters}
        chapter_rows = [
            {
                "chapter": chapter,
                "activities": [activity for activity in course_activities if activity.chapter_number == chapter.number],
            }
            for chapter in course_chapters
        ]
        standalone_activities = [
            activity
            for activity in course_activities
            if activity.chapter_number is None or activity.chapter_number not in chapter_numbers
        ]
        course_rows.append(
            {
                "offering": offering,
                "course": course,
                "chapters": chapter_rows,
                "standalone_activities": standalone_activities,
                "activity_count": len(course_activities),
                "track_names": course_track_names.get(course.id, []),
            }
        )

    return templates.TemplateResponse(
        request,
        "instructor/cohort_detail.html",
        {
            "request": request,
            "cohort": cohort,
            "students": student_rows,
            "student_total": len(student_rows_all),
            "active_student_count": len(active_rows),
            "at_risk_count": at_risk_count,
            "average_progress": average_progress,
            "facilitators": facilitator_pairs,
            "course_rows": course_rows,
            "track_items": track_items,
            "pagination": pagination_context(total=len(student_rows_all), limit=limit, offset=offset),
        },
    )


def _hx_error(request: Request, target_id: str, message: str) -> HTMLResponse:
    """Render a small inline error fragment (finding #1/#3).

    ``create_track``/``add_courses_to_track``/the roster-track and
    roster-state handlers used to let a ``BadRequestError``/``NotFoundError``
    become a raw kernel-rendered 400/404 response, which htmx never swaps into
    ``hx-target="body"`` — so the page just sat there with no feedback. This
    always answers 200 (htmx swaps 200 responses) and, for an htmx caller,
    retargets the swap to the small per-form ``target_id`` div placed next to
    the form instead of ``body`` — ``hx-target="body"`` on the form itself is
    left alone, since ``HX-Redirect`` (the success path) ignores it anyway.
    """
    response = templates.TemplateResponse(
        request,
        "instructor/_form_error.html",
        {"request": request, "message": message},
    )
    if request.headers.get("HX-Request"):
        response.headers["HX-Retarget"] = f"#{target_id}"
        response.headers["HX-Reswap"] = "innerHTML"
    return response


def _assigned_course_ids(db: Session, *, tenant_id: UUID, instructor_id: UUID) -> set[UUID]:
    return set(instructor_assigned_course_ids(db, tenant_id=tenant_id, instructor_id=instructor_id))


def _authorable_courses(db: Session, *, tenant_id: UUID, person_id: UUID) -> list[Course]:
    stmt = select(Course).where(Course.tenant_id == tenant_id).order_by(Course.title)
    if _is_admin(db, tenant_id, person_id):
        return list(db.scalars(stmt).all())
    assigned_ids = _assigned_course_ids(db, tenant_id=tenant_id, instructor_id=person_id)
    if not assigned_ids:
        return []
    return list(db.scalars(stmt.where(Course.id.in_(assigned_ids))).all())


def _authorable_course_or_404(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID) -> Course:
    course = db.scalars(select(Course).where(Course.tenant_id == tenant_id).where(Course.id == course_id)).first()
    if course is None:
        raise HTTPException(status_code=404)
    if _is_admin(db, tenant_id, person_id):
        return course
    assigned_ids = _assigned_course_ids(db, tenant_id=tenant_id, instructor_id=person_id)
    if course.id not in assigned_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return course


@router.post("/cohorts/{cohort_id}/facilitators")
def add_cohort_facilitator(
    cohort_id: UUID,
    request: Request,
    facilitator_id: UUID = Form(...),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    if not _is_admin(db, tenant.id, person.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    assign_facilitator(
        db,
        tenant_id=tenant.id,
        cohort_id=cohort_id,
        person_id=facilitator_id,
        request=request,
    )
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/cohorts/{cohort_id}/facilitators/{facilitator_id}/remove")
def remove_cohort_facilitator(
    cohort_id: UUID,
    facilitator_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    actor_is_admin = _is_admin(db, tenant.id, person.id)
    if not actor_is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    remove_facilitator(
        db,
        tenant_id=tenant.id,
        cohort_id=cohort_id,
        person_id=facilitator_id,
        request=request,
    )
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/cohorts/{cohort_id}/enroll")
def enroll_student(
    cohort_id: UUID,
    request: Request,
    emails: str = Form(""),
    email: str = Form(""),
    track_id: str = Form(""),
    return_to: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Bulk-enroll people by email; reports unknown emails instead of silently
    dropping them (finding #6). Accepts ``emails`` (textarea) and/or ``email``.

    Reactivating a non-student (e.g. instructor-role) enrollment is
    admin-only (see ``activate_enrollment``). ``bulk_enroll`` never raises for
    this — a non-admin instructor's attempt is reported in the summary as
    "Requires admin to reactivate", the same per-email-outcome contract as
    an unknown email, and the rest of the batch is still processed.
    """
    tenant = require_tenant(request)
    # bulk_enroll raises NotFoundError (-> 404) when the cohort is not in-tenant.
    track_uuid = UUID(track_id) if track_id else None
    result = bulk_enroll(
        db,
        tenant_id=tenant.id,
        cohort_id=cohort_id,
        emails=_split_emails(emails, email),
        track_id=track_uuid,
        request=request,
    )
    enrolled = len(result["enrolled"])
    reactivated = len(result["reactivated"])
    already_active = len(result["already_active"])
    summary = f"Enrolled {enrolled}."
    if reactivated:
        summary += f" Reactivated {reactivated}."
    if already_active:
        summary += f" Already active: {already_active}."
    if result["admin_required"]:
        summary += " Requires admin to reactivate: " + ", ".join(_e(e) for e in result["admin_required"]) + "."
    if result["not_found"]:
        summary += " Unknown (not enrolled): " + ", ".join(_e(e) for e in result["not_found"]) + "."
    target = _cohort_action_target(cohort_id, return_to)
    if (
        request.headers.get("HX-Request")
        and target != "/instructor/cohorts"
        and not (result["admin_required"] or result["not_found"])
    ):
        return hx_redirect(request, target)
    if request.headers.get("HX-Request"):
        return HTMLResponse(f'<div class="enroll-summary" role="status">{summary}</div>')
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/roster/{person_id}/state")
def change_roster_state(
    cohort_id: UUID,
    person_id: UUID,
    request: Request,
    state: str = Form(...),
    return_to: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Drop / waitlist / reactivate a roster member (finding #6).

    A plain instructor may change a ``student``-role enrollment's state. Only
    an admin may change a non-student (e.g. ``instructor``) enrollment's
    state — dropping a fellow instructor's own enrollment silently strips
    their authoring access (``_assigned_course_ids``), so this must not be
    reachable by any instructor with a UI button, not just a crafted request.
    """
    tenant = require_tenant(request)
    target = db.scalars(
        select(Enrollment)
        .where(Enrollment.tenant_id == tenant.id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.person_id == person_id)
    ).first()
    actor_is_admin = False
    if target is not None and target.role_in_cohort != "student":
        actor_is_admin = _is_admin(db, tenant.id, person.id)
        if not actor_is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    try:
        set_roster_state(
            db,
            tenant_id=tenant.id,
            cohort_id=cohort_id,
            person_id=person_id,
            state=state,
            request=request,
        )
    except NotFoundError as exc:
        return _hx_error(request, f"roster-state-error-{cohort_id}-{person_id}", str(exc))
    return hx_redirect(request, _cohort_action_target(cohort_id, return_to))


async def _positions_from_form(request: Request, course_ids: list[UUID]) -> dict[UUID, int]:
    """Read optional ``position_<course_id>`` fields for the given course ids.

    A blank/absent position input is fine — that course is simply left
    unpositioned (appended after any positioned courses in submission
    order); a non-integer value is treated the same as absent.
    """
    form = await request.form()
    positions: dict[UUID, int] = {}
    for course_id in course_ids:
        raw = form.get(f"position_{course_id}")
        if not raw:
            continue
        try:
            positions[course_id] = int(str(raw))
        except ValueError:
            continue
    return positions


@router.post("/cohorts/{cohort_id}/tracks")
async def create_track_for_cohort(
    cohort_id: UUID,
    request: Request,
    name: str = Form(...),
    course_ids: list[str] = Form([]),
    course_id: str = Form(""),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    selected: list[UUID] = []
    for raw in [*course_ids, course_id]:
        if raw:
            selected.append(UUID(raw))
    positions = await _positions_from_form(request, selected)
    try:
        track_svc.create_cohort_track(
            db, tenant_id=tenant.id, cohort_id=cohort_id, name=name, course_ids=selected, positions=positions
        )
    except (BadRequestError, NotFoundError) as exc:
        return _hx_error(request, f"track-form-error-{cohort_id}", str(exc))
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/cohorts/{cohort_id}/tracks/{track_id}/courses")
async def add_courses_to_track(
    cohort_id: UUID,
    track_id: UUID,
    request: Request,
    course_ids: list[str] = Form([]),
    course_id: str = Form(""),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    selected: list[UUID] = []
    for raw in [*course_ids, course_id]:
        if raw:
            selected.append(UUID(raw))
    positions = await _positions_from_form(request, selected)
    try:
        track_svc.add_courses_to_cohort_track(
            db,
            tenant_id=tenant.id,
            cohort_id=cohort_id,
            track_id=track_id,
            course_ids=selected,
            positions=positions,
        )
    except (BadRequestError, NotFoundError) as exc:
        return _hx_error(request, f"track-courses-error-{track_id}", str(exc))
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/tracks/{track_id}/reorder")
async def reorder_track(
    track_id: UUID,
    request: Request,
    course_ids: list[str] = Form([]),
    db: Session = Depends(get_db),
):
    """Reorder an EXISTING track's courses (not just at creation).

    A Track is tenant-level, not cohort-scoped (CohortTrack is the join), so
    this route is not nested under a specific cohort. Gated the same as
    other track-management actions (require_web_role("instructor"), already
    the router-level default) — this is not the admin-only case.
    """
    tenant = require_tenant(request)
    submitted: list[UUID] = [UUID(raw) for raw in course_ids if raw]
    form = await request.form()
    ranked: list[tuple[int, int, UUID]] = []
    for idx, course_id in enumerate(submitted):
        raw_pos = form.get(f"position_{course_id}")
        try:
            pos = int(str(raw_pos)) if raw_pos else idx
        except ValueError:
            pos = idx
        ranked.append((pos, idx, course_id))
    ranked.sort(key=lambda t: (t[0], t[1]))
    ordered = [course_id for _, _, course_id in ranked]
    try:
        track_svc.reorder_track_courses(db, tenant_id=tenant.id, track_id=track_id, ordered_course_ids=ordered)
    except (BadRequestError, NotFoundError) as exc:
        return _hx_error(request, f"track-reorder-error-{track_id}", str(exc))
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/cohorts/{cohort_id}/roster/{person_id}/track")
def change_roster_track(
    cohort_id: UUID,
    person_id: UUID,
    request: Request,
    track_id: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    try:
        track_svc.assign_enrollment_track(
            db, tenant_id=tenant.id, cohort_id=cohort_id, person_id=person_id, track_id=UUID(track_id)
        )
    except NotFoundError as exc:
        return _hx_error(request, f"roster-track-error-{cohort_id}-{person_id}", str(exc))
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/cohorts/{cohort_id}/roster/{person_id}/track/clear")
def clear_roster_track(
    cohort_id: UUID,
    person_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Admin-only recovery: null out a stuck learner's track assignment.

    Deliberately admin-gated regardless of the target's role — clearing a
    learner's track is a bigger structural change than a routine
    drop/reactivate (mirrors the admin gate already used in
    change_roster_state above).
    """
    tenant = require_tenant(request)
    if not _is_admin(db, tenant.id, person.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    try:
        track_svc.clear_enrollment_track(db, tenant_id=tenant.id, cohort_id=cohort_id, person_id=person_id)
    except NotFoundError as exc:
        return _hx_error(request, f"roster-track-clear-error-{cohort_id}-{person_id}", str(exc))
    return hx_redirect(request, "/instructor/cohorts")


@router.post("/cohorts/{cohort_id}/invite")
def invite_to_cohort(
    cohort_id: UUID,
    request: Request,
    email: str = Form(...),
    first_name: str = Form("New"),
    last_name: str = Form("Learner"),
    track_id: str = Form(""),
    return_to: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Invite a new person (no account yet) and enroll them — closes the #6 gap
    where unknown emails were silently dropped. Queues the activation email.

    Reactivating a non-student (e.g. instructor-role) enrollment through this
    form is admin-only (see ``activate_enrollment``); a non-admin instructor
    attempting it gets an inline error instead of silently restoring the
    target's authoring access.
    """
    tenant = require_tenant(request)
    track_uuid = UUID(track_id) if track_id else None
    cohort = cohort_fact(db, tenant_id=tenant.id, cohort_id=cohort_id)
    if cohort is None:
        raise NotFoundError("cohort not found for tenant")
    track = None
    if track_uuid is not None:
        cohort_track = track_svc.cohort_track_or_404(
            db,
            tenant_id=tenant.id,
            cohort_id=cohort_id,
            track_id=track_uuid,
        )
        track = track_fact(db, tenant_id=tenant.id, cohort_id=cohort_id, track_id=cohort_track.track_id)
    try:
        with invite_web_cohort_account(
            db,
            request=request,
            email=email,
            first_name=first_name,
            last_name=last_name,
            cohort_id=cohort.id,
            track_id=track.id if track is not None else None,
        ) as result:
            invited_person = result.person
            sent = False
            if result.token is not None:
                link = str(request.url_for("accept_form").include_query_params(token=result.token))
                link_e = _e(link)
                sent = enqueue_email(
                    db,
                    tenant_id=tenant.id,
                    idempotency_key=f"account-invite:{invited_person.id}:{hash_token(result.token)}",
                    kind="account_invite",
                    recipient=invited_person.email,
                    subject="You're invited to Dotmac Academy",
                    html_body=(
                        f"<p>Hi {_e(invited_person.first_name)},</p>"
                        f"<p>You have been invited to Dotmac Academy.</p>"
                        f'<p><a href="{link_e}">Set up your account</a></p>'
                        f"<p>If the button does not work, open this link: {link_e}</p>"
                    ),
                    text_body=(
                        f"Hi {invited_person.first_name},\n\n"
                        f"You have been invited to Dotmac Academy.\n\n"
                        f"Set up your account: {link}\n"
                    ),
                )
            if result.token is None:
                status = "Student enrolled. Existing account can sign in."
            else:
                status = "Invite email queued." if sent else "Invite email could not be queued."
            target = _cohort_action_target(cohort_id, return_to)
            if request.headers.get("HX-Request") and target != "/instructor/cohorts":
                return hx_redirect(request, target)
            # Surface _apply_assignment's descriptions (e.g. "reactivated (was
            # dropped)", "already an instructor, role unchanged") — previously
            # computed but silently discarded on this surface.
            assignments_html = ""
            if result.assignments:
                items = "".join(f"<li>{_e(item)}</li>" for item in result.assignments)
                assignments_html = f'<ul class="mt-1 list-disc pl-5 text-ink-soft">{items}</ul>'
            return HTMLResponse(
                f'<div class="invite-summary rounded-lg bg-sand-100 p-3 text-sm" role="status">'
                f'<p class="font-semibold">{_e(status)}</p>'
                f"<p>Student: {_e(invited_person.email)}</p>"
                f"{assignments_html}"
                f"</div>"
            )
    except BadRequestError as exc:
        return _hx_error(request, f"invite-result-{cohort_id}", str(exc))


def _parse_dt(value: str | None) -> datetime | None:
    """Parse a datetime-local form value into a UTC-aware datetime.

    Instructors type wall-clock time in the academy's timezone
    (settings.academy_timezone, default Africa/Lagos); the localtime service
    owns the conversion and storage stays UTC.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid date/time.") from exc
    return local_to_utc(dt)


@router.get("/cohorts/{cohort_id}/timetable", response_class=HTMLResponse)
def cohort_timetable(cohort_id: UUID, request: Request, db: Session = Depends(get_db)):
    """A cohort's class-session timetable, with add/cancel controls."""
    tenant = require_tenant(request)
    cohort = cohort_or_404(db, tenant_id=tenant.id, cohort_id=cohort_id)
    sessions = scheduling.list_for_cohort(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(
        request,
        "instructor/timetable.html",
        {
            "request": request,
            "cohort": cohort,
            "sessions": sessions,
            "session_types": list(scheduling.SESSION_TYPES),
            "default_session_type": cast(str, effective(db, require_store=True)["learning_default_session_type"]),
            "delivery_modes": sorted(scheduling.DELIVERY_MODES),
        },
    )


@router.post("/cohorts/{cohort_id}/sessions")
def create_class_session(
    cohort_id: UUID,
    request: Request,
    title: str = Form(...),
    starts_at: str = Form(...),
    session_type: str | None = Form(None),
    ends_at: str = Form(""),
    location: str = Form(""),
    join_url: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cohort_or_404(db, tenant_id=tenant.id, cohort_id=cohort_id)
    starts = _parse_dt(starts_at)
    if starts is None:
        raise HTTPException(status_code=400, detail="A start time is required.")
    try:
        scheduling.create_session(
            db,
            tenant_id=tenant.id,
            cohort_id=cohort_id,
            title=title,
            session_type=session_type,
            starts_at=starts,
            ends_at=_parse_dt(ends_at),
            location=location or None,
            join_url=join_url or None,
            notes=notes or None,
        )
    except (BadRequestError, NotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _timetable_redirect(request, cohort_id)


@router.post("/sessions/{session_id}/cancel")
def cancel_class_session(session_id: UUID, request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    try:
        session = scheduling.cancel_session(db, tenant_id=tenant.id, session_id=session_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404) from exc
    return _timetable_redirect(request, session.cohort_id)


@router.get("/sessions/{session_id}/edit", response_class=HTMLResponse)
def edit_class_session_form(session_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Edit form for a single session (start time shown/edited in academy time)."""
    tenant = require_tenant(request)
    try:
        session = scheduling.get_session(db, tenant_id=tenant.id, session_id=session_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404) from exc
    cohort = cohort_or_404(db, tenant_id=tenant.id, cohort_id=session.cohort_id)
    return templates.TemplateResponse(
        request,
        "instructor/session_edit.html",
        {
            "request": request,
            "cohort": cohort,
            "session": session,
            "session_types": list(scheduling.SESSION_TYPES),
        },
    )


@router.post("/sessions/{session_id}/edit")
def edit_class_session(
    session_id: UUID,
    request: Request,
    title: str = Form(...),
    starts_at: str = Form(...),
    session_type: str | None = Form(None),
    ends_at: str = Form(""),
    location: str = Form(""),
    join_url: str = Form(""),
    notes: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    starts = _parse_dt(starts_at)
    if starts is None:
        raise HTTPException(status_code=400, detail="A start time is required.")
    if session_type is None:
        session_type = cast(str, effective(db, require_store=True)["learning_default_session_type"])
    try:
        session, changes = scheduling.update_session(
            db,
            request=request,
            tenant_id=tenant.id,
            session_id=session_id,
            title=title,
            starts_at=starts,
            ends_at=_parse_dt(ends_at),
            session_type=session_type,
            location=location,
            join_url=join_url,
            notes=notes,
        )
    except (BadRequestError, NotFoundError) as exc:
        code = 404 if isinstance(exc, NotFoundError) else 400
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    return _timetable_redirect(request, session.cohort_id)


@router.post("/cohorts/{cohort_id}/delivery-mode")
def set_cohort_delivery_mode(
    cohort_id: UUID,
    request: Request,
    mode: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cohort_or_404(db, tenant_id=tenant.id, cohort_id=cohort_id)
    try:
        scheduling.set_delivery_mode(db, tenant_id=tenant.id, cohort_id=cohort_id, mode=mode)
    except BadRequestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _timetable_redirect(request, cohort_id)


def _timetable_redirect(request: Request, cohort_id: UUID) -> Response:
    target = f"/instructor/cohorts/{cohort_id}/timetable"
    return hx_redirect(request, target)


@router.post("/people/{person_id}/status", dependencies=[Depends(require_web_role("admin"))])
def change_account_status(
    person_id: UUID,
    request: Request,
    status_value: str = Form(...),
    db: Session = Depends(get_db),
):
    """Suspend or reactivate an account (finding #7).

    Admin-only: account suspension is privileged, so a plain instructor cannot
    suspend admins or peer instructors (the whole route requires the admin role).
    """
    tenant = require_tenant(request)
    set_account_status(db, tenant_id=tenant.id, person_id=person_id, status=status_value)
    return hx_redirect(request, "/instructor/cohorts")


@router.get("/courses", response_class=HTMLResponse)
def author_courses_list(
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Instructor content management scoped to assigned courses."""
    tenant = require_tenant(request)
    is_admin = _is_admin(db, tenant.id, person.id)
    courses = _authorable_courses(db, tenant_id=tenant.id, person_id=person.id)
    return templates.TemplateResponse(
        request,
        "instructor/courses.html",
        {"request": request, "courses": courses, "is_admin": is_admin},
    )


@router.post("/courses")
def author_create_course(
    request: Request,
    slug: str = Form(...),
    title: str = Form(...),
    discipline: str = Form(...),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Create a new draft course in-app. Admin-only because assignment is admin-owned."""
    tenant = require_tenant(request)
    if not _is_admin(db, tenant.id, person.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create courses")
    course = create_course(db, tenant_id=tenant.id, slug=slug, title=title, discipline=discipline)
    target = f"/instructor/courses/{course.id}/edit"
    return hx_redirect(request, target)


@router.get("/courses/{course_id}/edit", response_class=HTMLResponse)
def author_course_page(
    course_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Authoring page for an assigned course."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    chapters = authoring_chapters(db, tenant_id=tenant.id, course_id=course_id)
    chapter_rows = [{"chapter": chapter, "source": editable_chapter_source(chapter)} for chapter in chapters]
    return templates.TemplateResponse(
        request,
        "instructor/authoring.html",
        {"request": request, "course": course, "chapters": chapter_rows},
    )


@router.get("/courses/{course_id}/preview", response_class=HTMLResponse)
def preview_course(
    course_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Read-only instructor preview for an assigned course."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    chapters = authoring_chapters(db, tenant_id=tenant.id, course_id=course.id)
    chapter = chapters[0] if chapters else None
    return _preview_course_response(request, db, tenant.id, course, chapters, chapter)


@router.get("/courses/{course_id}/preview/chapters/{chapter_number}", response_class=HTMLResponse)
def preview_course_chapter(
    course_id: UUID,
    chapter_number: int,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Read-only instructor preview for one chapter in an assigned course."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    chapters = authoring_chapters(db, tenant_id=tenant.id, course_id=course.id)
    chapter = next((row for row in chapters if row.number == chapter_number), None)
    if chapter is None:
        raise HTTPException(status_code=404)
    return _preview_course_response(request, db, tenant.id, course, chapters, chapter)


def _preview_course_response(
    request: Request,
    db: Session,
    tenant_id: UUID,
    course: Course,
    chapters: Sequence[ChapterFact],
    chapter: ChapterFact | None,
) -> HTMLResponse:
    activity = None
    reading_minutes = 0
    previous_chapter = None
    next_chapter = None
    if chapter is not None:
        activity = db.scalars(
            select(Activity)
            .where(Activity.tenant_id == tenant_id)
            .where(Activity.course_id == course.id)
            .where(Activity.chapter_number == chapter.number)
        ).first()
        words = len(re.sub(r"<[^>]+>", " ", chapter.body_html or "").split())
        reading_minutes = learning_policy.reading_minutes(db, words)
        previous_chapter = next((row for row in reversed(chapters) if row.number < chapter.number), None)
        next_chapter = next((row for row in chapters if row.number > chapter.number), None)
    return templates.TemplateResponse(
        request,
        "instructor/course_preview.html",
        {
            "request": request,
            "course": course,
            "chapters": chapters,
            "chapter": chapter,
            "activity": activity,
            "reading_minutes": reading_minutes,
            "previous_chapter": previous_chapter,
            "next_chapter": next_chapter,
        },
    )


@router.post("/courses/{course_id}/chapters")
def author_upsert_chapter(
    course_id: UUID,
    request: Request,
    number: int = Form(...),
    title: str = Form(...),
    body_md: str = Form(...),
    part: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Create or update a chapter for an assigned course."""
    tenant = require_tenant(request)
    _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    upsert_chapter(db, tenant_id=tenant.id, course_id=course_id, number=number, title=title, body_md=body_md, part=part)
    target = f"/instructor/courses/{course_id}/edit"
    return hx_redirect(request, target)


@router.post("/courses/{course_id}/chapters/{chapter_id}/delete")
def author_delete_chapter(
    course_id: UUID,
    chapter_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Delete a chapter from an assigned course."""
    tenant = require_tenant(request)
    _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    delete_chapter(db, tenant_id=tenant.id, course_id=course_id, chapter_id=chapter_id)
    target = f"/instructor/courses/{course_id}/edit"
    return hx_redirect(request, target)


@router.post("/courses/{course_id}/status")
def set_course_status(
    course_id: UUID,
    request: Request,
    status_value: str = Form(...),
    person: AcademyCurrentAccount = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Set lifecycle status for an assigned course."""
    tenant = require_tenant(request)
    if status_value not in ("draft", "published", "completed"):
        raise HTTPException(status_code=400, detail="invalid status")
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    course.status = status_value
    target = f"/instructor/courses/{course_id}/edit"
    return hx_redirect(request, target)


@router.get("/results", response_class=HTMLResponse)
def results(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    rows = db.execute(
        select(Party.email, Activity.title, Score)
        .select_from(Party)
        .join(PartyPerson, PartyPerson.party_id == Party.id)
        .join(
            AcademyAccountProfile,
            (AcademyAccountProfile.party_id == Party.id) & (AcademyAccountProfile.tenant_id == Party.tenant_id),
        )
        .join(
            Submission,
            (Submission.person_id == Party.id) & (Submission.tenant_id == Party.tenant_id),
        )
        .join(
            Activity,
            (Activity.id == Submission.activity_id) & (Activity.tenant_id == Submission.tenant_id),
        )
        .join(
            Score,
            (Score.submission_id == Submission.id) & (Score.tenant_id == Submission.tenant_id),
        )
        .where(Party.tenant_id == tenant.id, Party.party_type == PartyType.person)
    ).all()
    return templates.TemplateResponse(request, "instructor/results.html", {"request": request, "rows": rows})


@router.get("/grading", response_class=HTMLResponse)
def grading_queue(request: Request, db: Session = Depends(get_db)):
    """Manual grading queue: submissions awaiting a score (finding #4)."""
    tenant = require_tenant(request)
    rows = [
        {"submission_id": sub.id, "activity_title": act.title, "email": email, "attempt_no": sub.attempt_no}
        for sub, act, email in pending_grading(db, tenant_id=tenant.id)
    ]
    return templates.TemplateResponse(request, "instructor/grading.html", {"request": request, "rows": rows})


@router.get("/dashboard/cohort/{cohort_id}", response_class=HTMLResponse)
def cohort_dashboard(cohort_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Cohort progress + at-risk learners (finding #9)."""
    tenant = require_tenant(request)
    ov = cohort_overview(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(
        request,
        "instructor/dashboard_cohort.html",
        {"request": request, "cohort": ov["cohort"], "rows": ov["rows"]},
    )


@router.get("/items/{activity_id}", response_class=HTMLResponse)
def item_analytics(activity_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Per-question difficulty (p-value) for an activity (finding #4/#9)."""
    tenant = require_tenant(request)
    act = db.scalars(select(Activity).where(Activity.tenant_id == tenant.id).where(Activity.id == activity_id)).first()
    if act is None:
        raise HTTPException(status_code=404)
    items = item_analysis(db, tenant_id=tenant.id, activity_id=activity_id)
    return templates.TemplateResponse(
        request,
        "instructor/item_analytics.html",
        {"request": request, "activity": act, "items": items},
    )


@router.post("/scores/{submission_id}/override")
def override(
    submission_id: UUID,
    request: Request,
    score_value: float = Form(...),
    max_score: float = Form(...),
    reason: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    override_score(
        db,
        tenant_id=tenant.id,
        submission_id=submission_id,
        score_value=score_value,
        max_score=max_score,
        reason=reason,
    )
    return hx_redirect(request, "/instructor/results")


@router.post("/activities/{activity_id}/attempts/grant")
def grant_attempt(
    activity_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    person_id: UUID = Form(...),
    reason: str = Form(...),
    extra_attempts: int | None = Form(None),
    db: Session = Depends(get_db),
):
    """Give one learner another go at this activity.

    The alternative an instructor had was to raise ``max_attempts``, which
    reopens the activity for everyone on it. This is scoped to the learner and
    keeps the reason.
    """
    tenant = require_tenant(request)
    act = get_activity(db, tenant_id=tenant.id, activity_id=activity_id)
    if act is None:
        raise HTTPException(status_code=404)
    if act.max_attempts is None:
        # Nothing to grant: the activity is already uncapped, and recording a
        # grant against it would imply a limit that does not exist.
        raise HTTPException(status_code=400, detail="This activity has no attempt limit.")
    audit_context = AttemptAuditContext(
        tenant_id=tenant.id,
        actor_type="user",
        actor_id=str(person.id),
        source_application=resolve_event_attribution(None),
    )
    try:
        attempt_policy.grant_extra_attempt(
            db,
            tenant_id=tenant.id,
            person_id=person_id,
            activity_id=activity_id,
            reason=reason,
            granted_by=person.id,
            extra_attempts=extra_attempts,
            audit_context=audit_context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return hx_redirect(request, "/instructor/results")


@router.get("/announcements", response_class=HTMLResponse)
def announcements_list(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    anns = ann_svc.list_for_tenant(db, tenant_id=tenant.id)
    cohorts = list(db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all())
    cohort_map = {c.id: c.name for c in cohorts}
    return templates.TemplateResponse(
        request,
        "instructor/announcements.html",
        {"request": request, "announcements": anns, "cohorts": cohorts, "cohort_map": cohort_map},
    )


@router.post("/announcements")
def announcements_create(
    request: Request,
    person: AcademyCurrentAccount = Depends(require_web_user),
    title: str = Form(...),
    body_md: str = Form(...),
    cohort_id: str = Form(""),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cid: UUID | None = None
    if cohort_id:
        try:
            cid = UUID(cohort_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid cohort") from None
        # Reject a cohort that isn't this tenant's (avoids a cross-tenant FK 500).
        owns = db.scalar(select(Cohort.id).where(Cohort.tenant_id == tenant.id).where(Cohort.id == cid))
        if owns is None:
            raise HTTPException(status_code=400, detail="Unknown cohort")
    ann_svc.create(
        db,
        tenant_id=tenant.id,
        author_person_id=person.id,
        title=title,
        body_md=body_md,
        cohort_id=cid,
    )
    return hx_redirect(request, "/instructor/announcements")


@router.post("/announcements/{announcement_id}/delete")
def announcement_delete(
    announcement_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    ann_svc.delete(db, tenant_id=tenant.id, announcement_id=announcement_id)
    return hx_redirect(request, "/instructor/announcements")


# --- question-bank authoring (thin composition over Learning) -------------
#
# Learning owns every bank write and performs no role checks. Academy
# authorizes here: bank_author_roles + course assignment for draft work;
# publish/repoint/export/retire each have their own settings role list
# (admin-only by default). No handler commits: get_db owns the boundary.
# Lifecycle refusals re-render with an error and a normal return so
# Learning's staged refusal audit / refreshed lint state commits.

_BANK_ERRORS = (BankLifecycleError, BadRequestError, ValueError)


def _bank_course_or_404(db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID, bank_id: UUID):
    course = _authorable_course_or_404(db, tenant_id=tenant_id, person_id=person_id, course_id=course_id)
    try:
        bank = _banks.bank_or_404(db, tenant_id=tenant_id, bank_id=bank_id)
    except NotFoundError:
        raise HTTPException(status_code=404) from None
    if bank.course_id != course.id:
        raise HTTPException(status_code=404)
    return course, bank


def _bank_page(request, *, course, bank, db, tenant_id, error=None, notice=None, violations=(), edit=None):
    history = _banks.version_history(db, tenant_id=tenant_id, bank_id=bank.id)
    draft = next((fact for fact in history if fact.state == "draft"), None)
    draft_questions = ()
    if draft is not None:
        draft_questions = _banks.version_questions(db, tenant_id=tenant_id, version_id=draft.id).questions
    activities = list(
        db.scalars(
            select(Activity)
            .where(Activity.tenant_id == tenant_id)
            .where(Activity.bank_id == bank.id)
            .order_by(Activity.title)
        ).all()
    )
    return templates.TemplateResponse(
        request,
        "instructor/bank.html",
        {
            "request": request,
            "course": course,
            "bank": bank,
            "history": history,
            "draft": draft,
            "draft_questions": draft_questions,
            "activities": activities,
            "error": error,
            "notice": notice,
            "violations": list(violations),
            "edit": edit,
        },
    )


@router.get("/courses/{course_id}/banks", response_class=HTMLResponse)
def course_banks(
    course_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    banks = _banks.list_course_banks(db, tenant_id=tenant.id, course_id=course.id)
    histories = {bank.id: _banks.version_history(db, tenant_id=tenant.id, bank_id=bank.id) for bank in banks}
    return templates.TemplateResponse(
        request,
        "instructor/banks.html",
        {"request": request, "course": course, "banks": banks, "histories": histories, "error": None, "notice": None},
    )


@router.post("/courses/{course_id}/banks/drafts")
def bank_create_draft(
    course_id: UUID,
    request: Request,
    kind: str = Form(...),
    chapter_number: str = Form(""),
    from_empty: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    chapter = int(chapter_number) if chapter_number.strip() else None
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    try:
        fact = _banks.create_draft(
            db,
            tenant_id=tenant.id,
            course_id=course.id,
            chapter_number=chapter,
            kind=kind.strip(),
            context=context,
            from_empty=bool(from_empty),
        )
    except _BANK_ERRORS as exc:  # lifecycle refusal: show it, keep audit staged writes
        banks = _banks.list_course_banks(db, tenant_id=tenant.id, course_id=course.id)
        histories = {b.id: _banks.version_history(db, tenant_id=tenant.id, bank_id=b.id) for b in banks}
        return templates.TemplateResponse(
            request,
            "instructor/banks.html",
            {"request": request, "course": course, "banks": banks, "histories": histories,
             "error": str(exc), "notice": None},
            status_code=400,
        )
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{fact.bank_id}")


@router.post("/courses/{course_id}/banks/import")
async def bank_import_yaml(
    course_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    """Upload YAML as a draft for this course. Never publishes."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    form = await request.form()
    upload = form.get("bank_file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail="bank_file is required")
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    try:
        # Decode + parse inside the handled region: malformed uploads
        # (non-UTF8, bad YAML, missing keys) render the error page with
        # a content-free message instead of a 500.
        text = _banks.decode_bank_text(await upload.read())
        report = _banks.import_yaml_as_draft(
            db,
            tenant_id=tenant.id,
            course_id=course.id,
            text=text,
            context=context,
            replace_imported_draft=bool(form.get("replace_imported_draft")),
        )
    except _BANK_ERRORS as exc:
        banks = _banks.list_course_banks(db, tenant_id=tenant.id, course_id=course.id)
        histories = {b.id: _banks.version_history(db, tenant_id=tenant.id, bank_id=b.id) for b in banks}
        return templates.TemplateResponse(
            request,
            "instructor/banks.html",
            {"request": request, "course": course, "banks": banks, "histories": histories,
             "error": str(exc), "notice": None},
            status_code=400,
        )
    if report.version_id is None:
        return hx_redirect(request, f"/instructor/courses/{course_id}/banks")
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{report.bank_id}")


@router.get("/courses/{course_id}/banks/{bank_id}", response_class=HTMLResponse)
def bank_detail(
    course_id: UUID,
    bank_id: UUID,
    request: Request,
    edit: str = "",
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    edit_question = None
    if edit:
        draft = _banks.draft_of(db, tenant_id=tenant.id, bank_id=bank.id)
        if draft is not None:
            for question in _banks.version_questions(db, tenant_id=tenant.id, version_id=draft.id).questions:
                if question.ext_id == edit:
                    edit_question = question
                    break
    return _bank_page(request, course=course, bank=bank, db=db, tenant_id=tenant.id, edit=edit_question)


@router.post("/courses/{course_id}/banks/{bank_id}/draft/questions")
def bank_upsert_question(
    course_id: UUID,
    bank_id: UUID,
    request: Request,
    ext_id: str = Form(...),
    stem: str = Form(...),
    question_type: str = Form(...),
    rubric_category: str = Form(...),
    category: str = Form(""),
    weight: int = Form(...),
    options_text: str = Form(""),
    correct_text: str = Form(""),
    explanation: str = Form(""),
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    draft = _banks.draft_of(db, tenant_id=tenant.id, bank_id=bank.id)
    if draft is None:
        raise HTTPException(status_code=400, detail="Create a draft before editing questions")
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    try:
        write = _banks.draft_question_from_lines(
            ext_id=ext_id, stem=stem, type_=question_type, rubric_category=rubric_category,
            options_text=options_text, correct_text=correct_text, category=category,
            explanation=explanation, weight=weight,
        )
        _banks.upsert_question(db, tenant_id=tenant.id, version_id=draft.id, question=write, context=context)
    except _BANK_ERRORS as exc:
        return _bank_page(request, course=course, bank=bank, db=db, tenant_id=tenant.id, error=str(exc))
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{bank_id}")


@router.post("/courses/{course_id}/banks/{bank_id}/draft/questions/{ext_id}/delete")
def bank_delete_question(
    course_id: UUID,
    bank_id: UUID,
    ext_id: str,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    draft = _banks.draft_of(db, tenant_id=tenant.id, bank_id=bank.id)
    if draft is None:
        raise HTTPException(status_code=400, detail="No draft to edit")
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    _banks.delete_question(db, tenant_id=tenant.id, version_id=draft.id, ext_id=ext_id, context=context)
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{bank_id}")


@router.post("/courses/{course_id}/banks/{bank_id}/draft/discard")
def bank_discard_draft(
    course_id: UUID,
    bank_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    _course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    draft = _banks.draft_of(db, tenant_id=tenant.id, bank_id=bank.id)
    if draft is None:
        raise HTTPException(status_code=400, detail="No draft to discard")
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    _banks.discard_draft(db, tenant_id=tenant.id, version_id=draft.id, context=context)
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{bank_id}")


@router.post("/courses/{course_id}/banks/{bank_id}/draft/lint", response_class=HTMLResponse)
def bank_lint_draft(
    course_id: UUID,
    bank_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_author_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    draft = _banks.draft_of(db, tenant_id=tenant.id, bank_id=bank.id)
    if draft is None:
        raise HTTPException(status_code=400, detail="No draft to lint")
    result = _banks.lint_draft(db, tenant_id=tenant.id, version_id=draft.id, course_slug=course.slug)
    notice = "Lint clean." if not result.violations else f"{len(result.violations)} lint violation(s)."
    return _bank_page(
        request, course=course, bank=bank, db=db, tenant_id=tenant.id,
        notice=notice, violations=result.violations,
    )


@router.post("/courses/{course_id}/banks/{bank_id}/draft/publish")
def bank_publish(
    course_id: UUID,
    bank_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_publish_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    draft = _banks.draft_of(db, tenant_id=tenant.id, bank_id=bank.id)
    if draft is None:
        raise HTTPException(status_code=400, detail="No draft to publish")
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    try:
        _banks.publish(db, tenant_id=tenant.id, version_id=draft.id, context=context, course_slug=course.slug)
    except _BANK_ERRORS as exc:
        return _bank_page(request, course=course, bank=bank, db=db, tenant_id=tenant.id, error=str(exc))
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{bank_id}")


@router.post("/courses/{course_id}/banks/{bank_id}/versions/{version_id}/retire")
def bank_retire(
    course_id: UUID,
    bank_id: UUID,
    version_id: UUID,
    request: Request,
    reason: str = Form(...),
    person: AcademyCurrentAccount = Depends(require_bank_retire_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    if _banks.version_questions(db, tenant_id=tenant.id, version_id=version_id).version.bank_id != bank.id:
        raise HTTPException(status_code=404)
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    try:
        _banks.retire(db, tenant_id=tenant.id, version_id=version_id, reason=reason, context=context)
    except _BANK_ERRORS as exc:
        return _bank_page(request, course=course, bank=bank, db=db, tenant_id=tenant.id, error=str(exc))
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{bank_id}")


@router.post("/courses/{course_id}/banks/{bank_id}/versions/{version_id}/repoint")
def bank_repoint(
    course_id: UUID,
    bank_id: UUID,
    version_id: UUID,
    request: Request,
    activity_id: UUID = Form(...),
    person: AcademyCurrentAccount = Depends(require_bank_repoint_access),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    if _banks.version_questions(db, tenant_id=tenant.id, version_id=version_id).version.bank_id != bank.id:
        raise HTTPException(status_code=404)
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    try:
        _banks.repoint_activity(
            db, tenant_id=tenant.id, activity_id=activity_id, version_id=version_id, context=context
        )
    except _BANK_ERRORS as exc:
        return _bank_page(request, course=course, bank=bank, db=db, tenant_id=tenant.id, error=str(exc))
    return hx_redirect(request, f"/instructor/courses/{course_id}/banks/{bank_id}")


@router.get("/courses/{course_id}/banks/{bank_id}/versions/{version_id}/export")
def bank_export(
    course_id: UUID,
    bank_id: UUID,
    version_id: UUID,
    request: Request,
    person: AcademyCurrentAccount = Depends(require_bank_export_access),
    db: Session = Depends(get_db),
):
    """Download one version as YAML (audited; contains answer keys)."""
    tenant = require_tenant(request)
    course, bank = _bank_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id, bank_id=bank_id
    )
    facts = _banks.version_questions(db, tenant_id=tenant.id, version_id=version_id)
    if facts.version.bank_id != bank.id:
        raise HTTPException(status_code=404)
    context = _banks.web_bank_audit_context(tenant_id=tenant.id, account=person)
    text = _banks.export_yaml(
        db, tenant_id=tenant.id, version_id=version_id, course_slug=course.slug, context=context
    )
    filename = f"bank-{course.slug}-{bank.kind}-v{facts.version.version_no or 'draft'}.yaml"
    return Response(
        content=text,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
