# app/web/instructor.py
"""Instructor portal routes.

All routes are gated by require_web_role("instructor") — students and unauthenticated
users receive 403 or a redirect to /login respectively.

IMPORTANT: no db.commit() calls inside any handler. The get_db dependency manages the
transaction: it does SET LOCAL app.current_tenant (transaction-scoped) and commits
after the response is built. A mid-handler commit would clear that GUC and break RLS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort, Enrollment
from app.models.course import Chapter, Course
from app.models.lab import LabTemplate
from app.models.person import Person
from app.services.assessment import override_score
from app.services.web_auth import require_web_role
from app.web.templating import templates

router = APIRouter(
    prefix="/instructor",
    dependencies=[Depends(require_tenant), Depends(require_web_role("instructor"))],
)

COURSE_STATUSES = ("draft", "active", "finished", "archived")


def _course_or_404(db: Session, *, tenant_id: UUID, course_id: UUID) -> Course:
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant_id).where(Course.id == course_id)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    return course


def _validate_course_status(status_value: str) -> str:
    status_value = status_value.strip().lower()
    if status_value not in COURSE_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid course status")
    return status_value


def _apply_course_status(course: Course, status_value: str) -> None:
    status_value = _validate_course_status(status_value)
    course.status = status_value
    course.finished_at = (
        course.finished_at or datetime.now(UTC)
        if status_value == "finished"
        else None
    )


def _matching_courses(db: Session, *, tenant_id: UUID, discipline: str) -> list[Course]:
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tenant_id)
            .where(Course.discipline == discipline)
            .order_by(Course.title)
        ).all()
    )


def _active_student_ids_for_discipline(
    db: Session, *, tenant_id: UUID, discipline: str
) -> set[UUID]:
    """Students with active access to courses in this discipline.

    The current data model has no direct course-enrollment table. Course access is
    resolved through active student enrollments in cohorts with the same discipline.
    """
    return set(
        db.scalars(
            select(Enrollment.person_id)
            .join(
                Cohort,
                (Cohort.id == Enrollment.cohort_id)
                & (Cohort.tenant_id == Enrollment.tenant_id),
            )
            .where(Enrollment.tenant_id == tenant_id)
            .where(Enrollment.role_in_cohort == "student")
            .where(Enrollment.status == "active")
            .where(Cohort.discipline == discipline)
            .where(Cohort.status == "active")
            .distinct()
        ).all()
    )


def _ensure_student_enrollment(
    db: Session, *, tenant_id: UUID, cohort_id: UUID, person_id: UUID
) -> bool:
    existing = db.scalars(
        select(Enrollment)
        .where(Enrollment.tenant_id == tenant_id)
        .where(Enrollment.cohort_id == cohort_id)
        .where(Enrollment.person_id == person_id)
    ).first()
    if existing is not None:
        if existing.role_in_cohort != "student" or existing.status != "active":
            existing.role_in_cohort = "student"
            existing.status = "active"
        return False

    db.add(
        Enrollment(
            tenant_id=tenant_id,
            cohort_id=cohort_id,
            person_id=person_id,
            role_in_cohort="student",
            status="active",
        )
    )
    return True


def _sync_matching_course_students(db: Session, *, tenant_id: UUID, cohort: Cohort) -> int:
    if not _matching_courses(db, tenant_id=tenant_id, discipline=cohort.discipline):
        return 0

    synced = 0
    for person_id in _active_student_ids_for_discipline(
        db, tenant_id=tenant_id, discipline=cohort.discipline
    ):
        if _ensure_student_enrollment(
            db,
            tenant_id=tenant_id,
            cohort_id=cohort.id,
            person_id=person_id,
        ):
            synced += 1
    return synced


def _sync_matching_course_students_for_discipline(
    db: Session, *, tenant_id: UUID, discipline: str
) -> None:
    cohorts = db.scalars(
        select(Cohort)
        .where(Cohort.tenant_id == tenant_id)
        .where(Cohort.discipline == discipline)
        .where(Cohort.status == "active")
    ).all()
    for cohort in cohorts:
        _sync_matching_course_students(db, tenant_id=tenant_id, cohort=cohort)


def _find_cohort_by_name(db: Session, *, tenant_id: UUID, name: str) -> Cohort | None:
    return db.scalars(
        select(Cohort)
        .where(Cohort.tenant_id == tenant_id)
        .where(func.lower(Cohort.name) == name.strip().lower())
        .order_by(Cohort.created_at)
    ).first()


@router.get("/cohorts", response_class=HTMLResponse)
def cohorts_list(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    cohorts = db.scalars(
        select(Cohort).where(Cohort.tenant_id == tenant.id).order_by(Cohort.name)
    ).all()
    cohort_rows = []
    for cohort in cohorts:
        students = db.scalars(
            select(Person)
            .join(
                Enrollment,
                (Enrollment.person_id == Person.id)
                & (Enrollment.tenant_id == Person.tenant_id),
            )
            .where(Enrollment.tenant_id == tenant.id)
            .where(Enrollment.cohort_id == cohort.id)
            .where(Enrollment.role_in_cohort == "student")
            .where(Enrollment.status == "active")
            .order_by(Person.last_name, Person.first_name, Person.email)
        ).all()
        courses = _matching_courses(db, tenant_id=tenant.id, discipline=cohort.discipline)
        cohort_rows.append(
            {
                "cohort": cohort,
                "course_rows": [
                    {
                        "course": course,
                        # Course access is cohort/discipline based, so every matching
                        # course has the cohort's active student enrollment list.
                        "students": students,
                    }
                    for course in courses
                ],
                "students": students,
            }
        )
    return templates.TemplateResponse(
        "instructor/cohorts.html", {"request": request, "cohort_rows": cohort_rows}
    )


@router.get("/courses", response_class=HTMLResponse)
def courses_list(request: Request, db: Session = Depends(get_db)):
    tenant = require_tenant(request)
    courses = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant.id)
        .order_by(Course.discipline, Course.title)
    ).all()
    return templates.TemplateResponse(
        "instructor/courses.html",
        {
            "request": request,
            "courses": courses,
            "statuses": COURSE_STATUSES,
        },
    )


@router.post("/courses")
def create_course(
    request: Request,
    title: str = Form(...),
    slug: str = Form(...),
    discipline: str = Form(...),
    description: str = Form(""),
    source_ref: str = Form("local-dev"),
    status_value: str = Form("active", alias="status"),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    slug = slug.strip()
    existing = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).where(Course.slug == slug)
    ).first()
    if existing is not None:
        raise HTTPException(status_code=400, detail="Course slug already exists")

    course = Course(
        tenant_id=tenant.id,
        title=title.strip(),
        slug=slug,
        discipline=discipline.strip(),
        description=description.strip(),
        source_ref=(source_ref.strip() or "local-dev"),
        status="active",
    )
    _apply_course_status(course, status_value)
    db.add(course)
    db.flush()

    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/courses"
        return resp
    return RedirectResponse("/instructor/courses", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/courses/{course_id}/edit", response_class=HTMLResponse)
def course_edit(
    course_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = _course_or_404(db, tenant_id=tenant.id, course_id=course_id)

    def _count(model) -> int:
        return int(
            db.scalar(
                select(func.count())
                .select_from(model)
                .where(model.tenant_id == tenant.id)
                .where(model.course_id == course.id)
            )
            or 0
        )

    counts = {
        "chapters": _count(Chapter),
        "labs": _count(LabTemplate),
        "assessments": _count(Activity),
    }
    return templates.TemplateResponse(
        "instructor/course_edit.html",
        {
            "request": request,
            "course": course,
            "statuses": COURSE_STATUSES,
            "counts": counts,
        },
    )


@router.post("/courses/{course_id}")
def update_course(
    course_id: UUID,
    request: Request,
    title: str = Form(...),
    slug: str = Form(...),
    discipline: str = Form(...),
    description: str = Form(""),
    source_ref: str = Form("local-dev"),
    status_value: str = Form("active", alias="status"),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = _course_or_404(db, tenant_id=tenant.id, course_id=course_id)
    slug = slug.strip()
    existing = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant.id)
        .where(Course.slug == slug)
        .where(Course.id != course.id)
    ).first()
    if existing is not None:
        raise HTTPException(status_code=400, detail="Course slug already exists")

    course.title = title.strip()
    course.slug = slug
    course.discipline = discipline.strip()
    course.description = description.strip()
    course.source_ref = source_ref.strip() or "local-dev"
    _apply_course_status(course, status_value)
    db.flush()

    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/courses"
        return resp
    return RedirectResponse("/instructor/courses", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/courses/{course_id}/finish")
def finish_course(
    course_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = _course_or_404(db, tenant_id=tenant.id, course_id=course_id)
    _apply_course_status(course, "finished")
    db.flush()

    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/courses"
        return resp
    return RedirectResponse("/instructor/courses", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts")
def create_cohort(
    request: Request,
    name: str = Form(...),
    discipline: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cohort = _find_cohort_by_name(db, tenant_id=tenant.id, name=name)
    if cohort is None:
        cohort = Cohort(
            tenant_id=tenant.id,
            name=name.strip(),
            discipline=discipline.strip(),
            status="active",
        )
        db.add(cohort)
        db.flush()
    _sync_matching_course_students(db, tenant_id=tenant.id, cohort=cohort)
    # No db.commit() here — get_db commits after the response is returned.
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cohorts/{cohort_id}/enroll")
def enroll_student(
    cohort_id: UUID,
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    cohort = db.scalars(
        select(Cohort).where(Cohort.id == cohort_id).where(Cohort.tenant_id == tenant.id)
    ).first()
    if cohort is None:
        raise HTTPException(status_code=404)
    person = db.scalars(
        select(Person)
        .where(Person.tenant_id == tenant.id)
        .where(Person.email == email)
    ).first()
    if person is not None:
        _ensure_student_enrollment(
            db,
            tenant_id=tenant.id,
            cohort_id=cohort_id,
            person_id=person.id,
        )
        db.flush()
        _sync_matching_course_students_for_discipline(
            db, tenant_id=tenant.id, discipline=cohort.discipline
        )
    hx = request.headers.get("HX-Request")
    if hx:
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = "/instructor/cohorts"
        return resp
    return RedirectResponse("/instructor/cohorts", status_code=status.HTTP_303_SEE_OTHER)


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
