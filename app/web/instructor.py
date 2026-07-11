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
from html import escape
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.course import Chapter, Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services import announcements as ann_svc
from app.services.analytics import item_analysis
from app.services.assessment import override_score, pending_grading
from app.services.authoring import create_course, delete_chapter, editable_chapter_source, upsert_chapter
from app.services.dashboards import cohort_overview
from app.services.email import send_email
from app.services.lifecycle import invite_user, set_account_status
from app.services.roles import role_slugs
from app.services.roster import bulk_enroll, set_roster_state
from app.services.web_auth import require_web_role, require_web_user
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


@router.get("/cohorts", response_class=HTMLResponse)
def cohorts_list(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    rows = db.scalars(
        select(Cohort).where(Cohort.tenant_id == tenant.id).order_by(Cohort.name)
    ).all()
    roster_rows = db.execute(
        select(Enrollment, Person)
        .join(
            Person,
            (Person.id == Enrollment.person_id)
            & (Person.tenant_id == Enrollment.tenant_id),
        )
        .where(Enrollment.tenant_id == tenant.id)
        .order_by(Person.last_name, Person.first_name, Person.email)
    ).all()
    roster_by_cohort: dict[UUID, list[dict]] = {cohort.id: [] for cohort in rows}
    for enrollment, student in roster_rows:
        if enrollment.cohort_id in roster_by_cohort:
            roster_by_cohort[enrollment.cohort_id].append(
                {"enrollment": enrollment, "person": student}
            )
    cohort_rows = [
        {"cohort": cohort, "roster": roster_by_cohort.get(cohort.id, [])}
        for cohort in rows
    ]
    return templates.TemplateResponse(
        "instructor/cohorts.html",
        {"request": request, "cohorts": rows, "cohort_rows": cohort_rows},
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
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


def _split_emails(*fields: str) -> list[str]:
    """Split one or more textarea/CSV email fields into a flat list."""
    out: list[str] = []
    for f in fields:
        for chunk in (f or "").replace(",", "\n").replace(";", "\n").split():
            out.append(chunk)
    return out


def _is_admin(db: Session, tenant_id: UUID, person_id: UUID) -> bool:
    return "admin" in role_slugs(db, tenant_id, person_id)


def _assigned_course_ids(db: Session, *, tenant_id: UUID, instructor_id: UUID) -> set[UUID]:
    rows = db.scalars(
        select(CourseOffering.course_id)
        .join(
            Enrollment,
            (Enrollment.cohort_id == CourseOffering.cohort_id)
            & (Enrollment.tenant_id == CourseOffering.tenant_id),
        )
        .where(CourseOffering.tenant_id == tenant_id)
        .where(CourseOffering.status == "active")
        .where(Enrollment.person_id == instructor_id)
        .where(Enrollment.role_in_cohort == "instructor")
        .where(Enrollment.status == "active")
    ).all()
    return set(rows)


def _authorable_courses(db: Session, *, tenant_id: UUID, person_id: UUID) -> list[Course]:
    stmt = select(Course).where(Course.tenant_id == tenant_id).order_by(Course.title)
    if _is_admin(db, tenant_id, person_id):
        return list(db.scalars(stmt).all())
    assigned_ids = _assigned_course_ids(db, tenant_id=tenant_id, instructor_id=person_id)
    if not assigned_ids:
        return []
    return list(db.scalars(stmt.where(Course.id.in_(assigned_ids))).all())


def _authorable_course_or_404(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID
) -> Course:
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant_id).where(Course.id == course_id)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    if _is_admin(db, tenant_id, person_id):
        return course
    assigned_ids = _assigned_course_ids(db, tenant_id=tenant_id, instructor_id=person_id)
    if course.id not in assigned_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return course




@router.post("/cohorts/{cohort_id}/enroll")
def enroll_student(
    cohort_id: UUID,
    request: Request,
    emails: str = Form(""),
    email: str = Form(""),
    db: Session = Depends(get_db),
):
    """Bulk-enroll people by email; reports unknown emails instead of silently
    dropping them (finding #6). Accepts ``emails`` (textarea) and/or ``email``."""
    tenant = require_tenant(request)
    # bulk_enroll raises NotFoundError (-> 404) when the cohort is not in-tenant.
    result = bulk_enroll(
        db, tenant_id=tenant.id, cohort_id=cohort_id,
        emails=_split_emails(emails, email),
    )
    enrolled = len(result["enrolled"]) + len(result["reactivated"])
    already_active = len(result["already_active"])
    summary = f"Enrolled {enrolled}."
    if already_active:
        summary += f" Already active: {already_active}."
    if result["not_found"]:
        summary += " Unknown (not enrolled): " + ", ".join(_e(e) for e in result["not_found"]) + "."
    if request.headers.get("HX-Request"):
        return HTMLResponse(f'<div class="enroll-summary" role="status">{summary}</div>')
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/roster/{person_id}/state")
def change_roster_state(
    cohort_id: UUID,
    person_id: UUID,
    request: Request,
    state: str = Form(...),
    db: Session = Depends(get_db),
):
    """Drop / waitlist / reactivate a roster member (finding #6)."""
    tenant = require_tenant(request)
    set_roster_state(db, tenant_id=tenant.id, cohort_id=cohort_id, person_id=person_id, state=state)
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/invite")
def invite_to_cohort(
    cohort_id: UUID,
    request: Request,
    email: str = Form(...),
    first_name: str = Form("New"),
    last_name: str = Form("Learner"),
    db: Session = Depends(get_db),
):
    """Invite a new person (no account yet) and enroll them — closes the #6 gap
    where unknown emails were silently dropped. Returns the activation link."""
    tenant = require_tenant(request)
    person, token = invite_user(db, tenant_id=tenant.id, email=email,
                                first_name=first_name, last_name=last_name, role="student")
    bulk_enroll(db, tenant_id=tenant.id, cohort_id=cohort_id, emails=[email])
    link = str(request.url_for("accept_form").include_query_params(token=token))
    link_e = _e(link)
    sent = send_email(
        person.email,
        "You're invited to Dotmac Academy",
        (
            f"<p>Hi {_e(person.first_name)},</p>"
            f"<p>You have been invited to Dotmac Academy.</p>"
            f"<p><a href=\"{link_e}\">Set up your account</a></p>"
            f"<p>If the button does not work, open this link: {link_e}</p>"
        ),
        text_body=(
            f"Hi {person.first_name},\n\n"
            f"You have been invited to Dotmac Academy.\n\n"
            f"Set up your account: {link}\n"
        ),
        db=db,
    )
    status = "Invite email sent." if sent else "Invite created. Email was not sent; use the activation link below."
    return HTMLResponse(
        f'<div class="invite-summary rounded-lg bg-sand-100 p-3 text-sm" role="status">'
        f'<p class="font-semibold">{_e(status)}</p>'
        f'<p>Student: {_e(person.email)}</p>'
        f'<p>Activation link: <a class="underline" href="{link_e}">{link_e}</a></p>'
        f'</div>'
    )


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
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/courses", response_class=HTMLResponse)
def author_courses_list(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Instructor content management scoped to assigned courses."""
    tenant = require_tenant(request)
    is_admin = _is_admin(db, tenant.id, person.id)
    courses = _authorable_courses(db, tenant_id=tenant.id, person_id=person.id)
    return templates.TemplateResponse(
        "instructor/courses.html",
        {"request": request, "courses": courses, "is_admin": is_admin},
    )


@router.post("/courses")
def author_create_course(
    request: Request,
    slug: str = Form(...),
    title: str = Form(...),
    discipline: str = Form(...),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Create a new draft course in-app. Admin-only because assignment is admin-owned."""
    tenant = require_tenant(request)
    if not _is_admin(db, tenant.id, person.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create courses")
    course = create_course(db, tenant_id=tenant.id, slug=slug, title=title, discipline=discipline)
    target = f"/instructor/courses/{course.id}/edit"
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = target
        return resp
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/courses/{course_id}/edit", response_class=HTMLResponse)
def author_course_page(
    course_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Authoring page for an assigned course."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id
    )
    chapters = db.scalars(
        select(Chapter).where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course_id).order_by(Chapter.number)
    ).all()
    chapter_rows = [
        {"chapter": chapter, "source": editable_chapter_source(chapter)}
        for chapter in chapters
    ]
    return templates.TemplateResponse(
        "instructor/authoring.html",
        {"request": request, "course": course, "chapters": chapter_rows},
    )


@router.get("/courses/{course_id}/preview", response_class=HTMLResponse)
def preview_course(
    course_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Read-only instructor preview for an assigned course."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id
    )
    chapters = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .order_by(Chapter.number)
    ).all()
    chapter = chapters[0] if chapters else None
    return _preview_course_response(request, db, tenant.id, course, chapters, chapter)


@router.get("/courses/{course_id}/preview/chapters/{chapter_number}", response_class=HTMLResponse)
def preview_course_chapter(
    course_id: UUID,
    chapter_number: int,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Read-only instructor preview for one chapter in an assigned course."""
    tenant = require_tenant(request)
    course = _authorable_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id
    )
    chapters = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .order_by(Chapter.number)
    ).all()
    chapter = next((row for row in chapters if row.number == chapter_number), None)
    if chapter is None:
        raise HTTPException(status_code=404)
    return _preview_course_response(request, db, tenant.id, course, chapters, chapter)


def _preview_course_response(
    request: Request,
    db: Session,
    tenant_id: UUID,
    course: Course,
    chapters: Sequence[Chapter],
    chapter: Chapter | None,
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
        reading_minutes = max(1, round(words / 200))
        previous_chapter = next((row for row in reversed(chapters) if row.number < chapter.number), None)
        next_chapter = next((row for row in chapters if row.number > chapter.number), None)
    return templates.TemplateResponse(
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
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Create or update a chapter for an assigned course."""
    tenant = require_tenant(request)
    _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    upsert_chapter(db, tenant_id=tenant.id, course_id=course_id, number=number,
                   title=title, body_md=body_md, part=part)
    target = f"/instructor/courses/{course_id}/edit"
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = target
        return resp
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/courses/{course_id}/chapters/{chapter_id}/delete")
def author_delete_chapter(
    course_id: UUID,
    chapter_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Delete a chapter from an assigned course."""
    tenant = require_tenant(request)
    _authorable_course_or_404(db, tenant_id=tenant.id, person_id=person.id, course_id=course_id)
    delete_chapter(db, tenant_id=tenant.id, course_id=course_id, chapter_id=chapter_id)
    target = f"/instructor/courses/{course_id}/edit"
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = target
        return resp
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/courses/{course_id}/status")
def set_course_status(
    course_id: UUID,
    request: Request,
    status_value: str = Form(...),
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Set lifecycle status for an assigned course."""
    tenant = require_tenant(request)
    if status_value not in ("draft", "published", "completed"):
        raise HTTPException(status_code=400, detail="invalid status")
    course = _authorable_course_or_404(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id
    )
    course.status = status_value
    target = f"/instructor/courses/{course_id}/edit"
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = target
        return resp
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/results", response_class=HTMLResponse)
def results(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    rows = db.execute(
        select(Person.email, Activity.title, Score)
        .join(
            Submission,
            (Submission.person_id == Person.id)
            & (Submission.tenant_id == Person.tenant_id),
        )
        .join(
            Activity,
            (Activity.id == Submission.activity_id)
            & (Activity.tenant_id == Submission.tenant_id),
        )
        .join(
            Score,
            (Score.submission_id == Submission.id)
            & (Score.tenant_id == Submission.tenant_id),
        )
        .where(Person.tenant_id == tenant.id)
    ).all()
    return templates.TemplateResponse(
        "instructor/results.html", {"request": request, "rows": rows}
    )


@router.get("/grading", response_class=HTMLResponse)
def grading_queue(request: Request, db: Session = Depends(get_db)):
    """Manual grading queue: submissions awaiting a score (finding #4)."""
    tenant = require_tenant(request)
    rows = [
        {"submission_id": sub.id, "activity_title": act.title, "email": email,
         "attempt_no": sub.attempt_no}
        for sub, act, email in pending_grading(db, tenant_id=tenant.id)
    ]
    return templates.TemplateResponse(
        "instructor/grading.html", {"request": request, "rows": rows}
    )


@router.get("/dashboard/cohort/{cohort_id}", response_class=HTMLResponse)
def cohort_dashboard(cohort_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Cohort progress + at-risk learners (finding #9)."""
    tenant = require_tenant(request)
    ov = cohort_overview(db, tenant_id=tenant.id, cohort_id=cohort_id)
    return templates.TemplateResponse(
        "instructor/dashboard_cohort.html",
        {"request": request, "cohort": ov["cohort"], "rows": ov["rows"]},
    )
@router.get("/items/{activity_id}", response_class=HTMLResponse)
def item_analytics(activity_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Per-question difficulty (p-value) for an activity (finding #4/#9)."""
    tenant = require_tenant(request)
    act = db.scalars(
        select(Activity).where(Activity.tenant_id == tenant.id).where(Activity.id == activity_id)
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    items = item_analysis(db, tenant_id=tenant.id, activity_id=activity_id)
    return templates.TemplateResponse(
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
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/results"
        return resp
    return RedirectResponse("/instructor/results", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/announcements", response_class=HTMLResponse)
def announcements_list(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    anns = ann_svc.list_for_tenant(db, tenant_id=tenant.id)
    cohorts = list(db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all())
    cohort_map = {c.id: c.name for c in cohorts}
    return templates.TemplateResponse(
        "instructor/announcements.html",
        {"request": request, "announcements": anns, "cohorts": cohorts, "cohort_map": cohort_map},
    )


@router.post("/announcements")
def announcements_create(
    request: Request,
    person: Person = Depends(require_web_user),
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
        owns = db.scalar(
            select(Cohort.id).where(Cohort.tenant_id == tenant.id).where(Cohort.id == cid)
        )
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
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/announcements"
        return resp
    return RedirectResponse("/instructor/announcements", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/announcements/{announcement_id}/delete")
def announcement_delete(
    announcement_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    ann_svc.delete(db, tenant_id=tenant.id, announcement_id=announcement_id)
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/announcements"
        return resp
    return RedirectResponse("/instructor/announcements", status_code=status.HTTP_303_SEE_OTHER)
