# app/web/learn.py
from __future__ import annotations

import re
from html.parser import HTMLParser
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Question, Score, Submission
from app.models.completion import CourseCompletion
from app.models.course import Chapter, Course
from app.models.person import Person
from app.models.reading import ChapterRead
from app.services import announcements as ann_svc
from app.services.assessment import attempts_used, best_scores_for, submit_activity
from app.services.attempts import close_open_attempt, open_or_create_attempt
from app.services.certificates import issue_certificate, render_certificate_pdf
from app.services.entitlements import accessible_course_ids, require_course_open
from app.services.pacing import require_activity_readable, require_activity_submittable
from app.services.roles import role_slugs
from app.services.web_auth import require_web_user
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_tenant)])


class _HeadingExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.headings: list[dict[str, str]] = []
        self._current_tag: str | None = None
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"h2", "h3"}:
            self._current_tag = tag
            self._parts = []

    def handle_data(self, data: str) -> None:
        if self._current_tag:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._current_tag:
            title = " ".join("".join(self._parts).split())
            if title:
                self.headings.append({"level": tag, "title": title})
            self._current_tag = None
            self._parts = []


def _slugify_heading(value: str) -> str:
    return (
        re.sub(r"-+", "-", re.sub(r"\s+", "-", re.sub(r"[^\w\s-]", "", (value or "").lower().strip())))[:64]
        or "section"
    )


_GROUPED_INTRO_HEADINGS = {"why-this-matters", "catch-up-sidebar"}


def _grouped_heading_key(value: str) -> str:
    return _slugify_heading(value).casefold()


def _chapter_subtopics(body_html: str) -> list[dict[str, str]]:
    parser = _HeadingExtractor()
    parser.feed(body_html or "")
    used: set[str] = set()
    subtopics: list[dict[str, str]] = []
    for heading in parser.headings:
        if _grouped_heading_key(heading["title"]) in _GROUPED_INTRO_HEADINGS:
            continue
        base = _slugify_heading(heading["title"])
        slug = base
        counter = 2
        while slug in used:
            slug = f"{base}-{counter}"
            counter += 1
        used.add(slug)
        subtopics.append({**heading, "slug": slug})
    return subtopics


def _enrolled_courses(db: Session, tid: UUID, person_id: UUID) -> list[Course]:
    """Courses the person can study, resolved Enrollment -> CourseOffering -> Course.

    Access requires an explicit CourseOffering linking the person's cohort to the
    course; sharing a ``discipline`` string no longer grants access.
    """
    course_ids = accessible_course_ids(db, tenant_id=tid, person_id=person_id)
    if not course_ids:
        return []
    return list(
        db.scalars(
            select(Course)
            .where(Course.tenant_id == tid)
            .where(Course.id.in_(course_ids))
            .order_by(Course.title)
        ).all()
    )


@router.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Student Learn Home — my courses (completion %), continue, recent results."""
    tenant = require_tenant(request)
    slugs = role_slugs(db, tenant.id, person.id)
    if "instructor" in slugs and "admin" not in slugs:
        return RedirectResponse("/instructor", status_code=303)
    enrolled = _enrolled_courses(db, tenant.id, person.id)

    # My courses: completion % = passed activities / total activities.
    my_courses: list[dict] = []
    best_by_course: dict = {}
    for course in enrolled:
        total = (
            db.scalar(
                select(func.count())
                .select_from(Activity)
                .where(Activity.tenant_id == tenant.id)
                .where(Activity.course_id == course.id)
            )
            or 0
        )
        best = best_scores_for(
            db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
        )
        best_by_course[course.id] = best
        passed = sum(1 for s in best.values() if s.passed)
        pct = round(100 * passed / total) if total else 0
        my_courses.append(
            {"course": course, "total": total, "passed": passed, "pct": pct}
        )

    # Continue: first incomplete chapter of the first enrolled course.
    continue_to = None
    for course in enrolled:
        passed_acts = {
            aid for aid, s in best_by_course.get(course.id, {}).items() if s.passed
        }
        chapters = db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
            .order_by(Chapter.number)
        ).all()
        for ch in chapters:
            act = db.scalars(
                select(Activity)
                .where(Activity.tenant_id == tenant.id)
                .where(Activity.course_id == course.id)
                .where(Activity.chapter_number == ch.number)
            ).first()
            if act is None or act.id not in passed_acts:
                continue_to = {"course": course, "chapter": ch}
                break
        if continue_to is not None:
            break

    # Recent results: the person's latest few scores (title + pass/fail + %).
    recent_rows = db.execute(
        select(Score, Activity.title)
        .join(
            Submission,
            (Submission.id == Score.submission_id)
            & (Submission.tenant_id == Score.tenant_id),
        )
        .join(
            Activity,
            (Activity.id == Submission.activity_id)
            & (Activity.tenant_id == Submission.tenant_id),
        )
        .where(Score.tenant_id == tenant.id)
        .where(Submission.person_id == person.id)
        .order_by(Score.created_at.desc())
        .limit(6)
    ).all()
    recent = [
        {"title": title, "passed": s.passed, "pct": round(100 * s.fraction)}
        for s, title in recent_rows
    ]

    latest_announcements = ann_svc.for_person(db, tenant_id=tenant.id, person_id=person.id, limit=3)

    return templates.TemplateResponse(
        "learn/home.html",
        {
            "request": request,
            "person": person,
            "my_courses": my_courses,
            "continue_to": continue_to,
            "recent": recent,
            "announcements": latest_announcements,
        },
    )


@router.get("/courses/{slug}/chapters/{n}", response_class=HTMLResponse)
def chapter(
    slug: str,
    n: int,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant.id)
        .where(Course.slug == slug)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=course.id)
    ch = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .where(Chapter.number == n)
    ).first()
    if ch is None:
        raise HTTPException(status_code=404)
    act = db.scalars(
        select(Activity)
        .where(Activity.tenant_id == tenant.id)
        .where(Activity.course_id == course.id)
        .where(Activity.chapter_number == n)
    ).first()
    total_chapters = int(db.scalar(
        select(func.count()).select_from(Chapter)
        .where(Chapter.tenant_id == tenant.id).where(Chapter.course_id == course.id)
    ) or 0)
    chapters = db.scalars(
        select(Chapter)
        .where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id)
        .order_by(Chapter.number)
    ).all()
    chapter_modules = [
        {"chapter": course_chapter, "subtopics": _chapter_subtopics(course_chapter.body_html)}
        for course_chapter in chapters
    ]
    chapter_ids = [chapter.id for chapter in chapters]
    completed_chapter_ids = (
        {
            row[0]
            for row in db.execute(
                select(ChapterRead.chapter_id)
                .where(ChapterRead.tenant_id == tenant.id)
                .where(ChapterRead.person_id == person.id)
                .where(ChapterRead.chapter_id.in_(chapter_ids))
            ).all()
        }
        if chapter_ids
        else set()
    )
    prev_ch = db.scalars(
        select(Chapter).where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id).where(Chapter.number < n)
        .order_by(Chapter.number.desc())
    ).first()
    next_ch = db.scalars(
        select(Chapter).where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id).where(Chapter.number > n)
        .order_by(Chapter.number)
    ).first()
    words = len(re.sub(r"<[^>]+>", " ", ch.body_html or "").split())
    reading_minutes = max(1, round(words / 200))
    completed = db.scalar(
        select(func.count()).select_from(ChapterRead)
        .where(ChapterRead.tenant_id == tenant.id)
        .where(ChapterRead.person_id == person.id)
        .where(ChapterRead.chapter_id == ch.id)
    ) or 0
    activity_taken = False
    if act is not None:
        activity_taken = attempts_used(
            db, tenant_id=tenant.id, person_id=person.id, activity_id=act.id
        ) > 0
    return templates.TemplateResponse(
        "chapter.html",
        {
            "request": request, "course": course, "chapter": ch, "activity": act,
            "total_chapters": total_chapters, "previous_chapter": prev_ch,
            "next_chapter": next_ch, "reading_minutes": reading_minutes,
            "completed": bool(completed), "activity_taken": activity_taken,
            "chapters": chapters, "chapter_modules": chapter_modules,
            "completed_chapter_ids": completed_chapter_ids,
            "completed_chapters": len(completed_chapter_ids),
        },
    )


@router.post("/courses/{slug}/chapters/{n}/complete", response_class=HTMLResponse)
def chapter_complete(
    slug: str,
    n: int,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    """Toggle a chapter's read-completion for the current learner (htmx)."""
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).where(Course.slug == slug)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    ch = db.scalars(
        select(Chapter).where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course.id).where(Chapter.number == n)
    ).first()
    if ch is None:
        raise HTTPException(status_code=404)
    existing = db.scalars(
        select(ChapterRead).where(ChapterRead.tenant_id == tenant.id)
        .where(ChapterRead.person_id == person.id).where(ChapterRead.chapter_id == ch.id)
    ).first()
    if existing is None:
        db.add(ChapterRead(tenant_id=tenant.id, person_id=person.id, chapter_id=ch.id))
        done = True
    else:
        db.delete(existing)
        done = False
    db.flush()
    return templates.TemplateResponse(
        "_mark_complete.html",
        {"request": request, "course": course, "chapter": ch, "completed": done},
    )


@router.get("/activities/{activity_id}", response_class=HTMLResponse)
def activity(
    activity_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    act = db.scalars(
        select(Activity)
        .where(Activity.id == activity_id)
        .where(Activity.tenant_id == tenant.id)
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)
    require_activity_readable(db, tenant_id=tenant.id, person_id=person.id,
                              course_id=act.course_id, activity_id=act.id)
    qs = db.scalars(
        select(Question)
        .where(Question.tenant_id == tenant.id)
        .where(Question.bank_id == act.bank_id)
    ).all()
    if act.question_count is not None:
        # Random pool: fix a subset+order for this attempt and render only those.
        attempt = open_or_create_attempt(
            db, tenant_id=tenant.id, person_id=person.id, activity_id=act.id,
            all_ext_ids=[q.ext_id for q in qs], count=act.question_count,
        )
        order = {eid: i for i, eid in enumerate(attempt.question_ext_ids)}
        qs = sorted((q for q in qs if q.ext_id in order), key=lambda q: order[q.ext_id])
    return templates.TemplateResponse(
        "activity.html", {"request": request, "activity": act, "questions": qs}
    )


@router.post("/activities/{activity_id}/submit", response_class=HTMLResponse)
async def submit(
    activity_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    act = db.scalars(
        select(Activity)
        .where(Activity.id == activity_id)
        .where(Activity.tenant_id == tenant.id)
    ).first()
    if act is None:
        raise HTTPException(status_code=404)
    require_course_open(db, tenant_id=tenant.id, person_id=person.id, course_id=act.course_id)
    require_activity_submittable(db, tenant_id=tenant.id, person_id=person.id,
                                 course_id=act.course_id, activity_id=act.id)
    if act.max_attempts is not None and attempts_used(
        db, tenant_id=tenant.id, person_id=person.id, activity_id=act.id
    ) >= act.max_attempts:
        raise HTTPException(status_code=403, detail="No attempts remaining")
    form = await request.form()
    # Random pool: grade exactly the subset this attempt was shown.
    only_ext_ids: list | None = None
    if act.question_count is not None:
        attempt = close_open_attempt(db, tenant_id=tenant.id, person_id=person.id,
                                     activity_id=act.id)
        only_ext_ids = list(attempt.question_ext_ids) if attempt is not None else []
    qs = db.scalars(
        select(Question)
        .where(Question.tenant_id == tenant.id)
        .where(Question.bank_id == act.bank_id)
    ).all()
    if only_ext_ids is not None:
        keep = set(only_ext_ids)
        qs = [q for q in qs if q.ext_id in keep]
    answers = {q.ext_id: form.getlist(q.ext_id) for q in qs}
    score = submit_activity(
        db,
        tenant_id=tenant.id,
        person_id=person.id,
        activity=act,
        answers=answers,
        only_ext_ids=only_ext_ids,
    )
    if score is None:
        # Manual-grading activity: submission is queued for the instructor.
        return HTMLResponse(
            '<div class="submit-pending" role="status">Submitted — your instructor '
            "will grade this and your result will appear once it's marked.</div>"
        )
    # get_db handles the final db.commit(); calling it here would expire ORM
    # objects and clear the SET LOCAL tenant config. Render from all bank questions
    # so retakes can display the originally recorded score, including random pools.
    display_questions = db.scalars(
        select(Question)
        .where(Question.tenant_id == tenant.id)
        .where(Question.bank_id == act.bank_id)
    ).all()
    by_id = {q.ext_id: q for q in display_questions}
    course = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant.id)
        .where(Course.id == act.course_id)
    ).first()
    next_chapter = None
    course_completion = None
    if course is not None and act.chapter_number is not None:
        next_chapter = db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
            .where(Chapter.number > act.chapter_number)
            .order_by(Chapter.number)
        ).first()
    if course is not None:
        course_completion = db.scalars(
            select(CourseCompletion)
            .where(CourseCompletion.tenant_id == tenant.id)
            .where(CourseCompletion.person_id == person.id)
            .where(CourseCompletion.course_id == course.id)
        ).first()
    return templates.TemplateResponse(
        "_activity_result.html",
        {
            "request": request,
            "score": score,
            "questions": by_id,
            "course": course,
            "next_chapter": next_chapter,
            "course_completion": course_completion,
        },
    )


@router.get("/progress", response_class=HTMLResponse)
def progress(
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
):
    tenant = require_tenant(request)
    best: dict = {}
    for course in _enrolled_courses(db, tenant.id, person.id):
        best.update(
            best_scores_for(
                db, tenant_id=tenant.id, person_id=person.id, course_id=course.id
            )
        )
    return templates.TemplateResponse(
        "progress.html", {"request": request, "best": list(best.values())}
    )


@router.get("/certificates/{course_id}")
def certificate(
    course_id: UUID,
    request: Request,
    person: Person = Depends(require_web_user),
    db: Session = Depends(get_db),
) -> Response:
    """Download the learner's PDF certificate for a completed course (403 if not)."""
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).where(Course.id == course_id)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    completion = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant.id)
        .where(CourseCompletion.person_id == person.id)
        .where(CourseCompletion.course_id == course_id)
    ).first()
    if completion is None or completion.status != "completed":
        raise HTTPException(status_code=403)
    cert = issue_certificate(
        db, tenant_id=tenant.id, person_id=person.id, course_id=course_id
    )
    pdf = render_certificate_pdf(
        recipient_name=f"{person.first_name} {person.last_name}".strip(),
        course_title=course.title,
        serial=cert.serial,
        issued_at=cert.issued_at,
    )
    filename = f"certificate-{course.slug}-{cert.serial}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
