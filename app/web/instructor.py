# app/web/instructor.py
"""Instructor portal routes.

All routes are gated by require_web_role("instructor") — students and unauthenticated
users receive 403 or a redirect to /login respectively.

IMPORTANT: no db.commit() calls inside any handler. The get_db dependency manages the
transaction: it does SET LOCAL app.current_tenant (transaction-scoped) and commits
after the response is built. A mid-handler commit would clear that GUC and break RLS.
"""

from __future__ import annotations

from html import escape
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_tenant
from app.models.assessment import Activity, Score, Submission
from app.models.cohort import Cohort
from app.models.course import Chapter, Course
from app.models.person import Person
from app.services.analytics import item_analysis
from app.services.assessment import override_score, pending_grading
from app.services.authoring import create_course, upsert_chapter
from app.services.dashboards import cohort_overview
from app.services.lifecycle import invite_user, set_account_status
from app.services.roster import bulk_enroll, set_roster_state
from app.services.web_auth import require_web_role
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
    rows = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all()
    return templates.TemplateResponse(
        "instructor/cohorts.html", {"request": request, "cohorts": rows}
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
    summary = f"Enrolled {enrolled}."
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
    link = f"/accept-invite?token={token}"
    link_e = _e(link)
    return HTMLResponse(
        f'<div class="invite-summary" role="status">Invited {_e(person.email)}. '
        f'Activation link: <a href="{link_e}">{link_e}</a></div>'
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


@router.post("/courses")
def author_create_course(
    request: Request,
    slug: str = Form(...),
    title: str = Form(...),
    discipline: str = Form(...),
    db: Session = Depends(get_db),
):
    """Create a new draft course in-app (finding #8)."""
    tenant = require_tenant(request)
    course = create_course(db, tenant_id=tenant.id, slug=slug, title=title, discipline=discipline)
    target = f"/instructor/courses/{course.id}/edit"
    if request.headers.get("HX-Request"):
        resp: Response = Response(status_code=200)
        resp.headers["HX-Redirect"] = target
        return resp
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/courses/{course_id}/edit", response_class=HTMLResponse)
def author_course_page(course_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Markdown authoring page: existing chapters + an add/edit form (finding #8)."""
    tenant = require_tenant(request)
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).where(Course.id == course_id)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    chapters = db.scalars(
        select(Chapter).where(Chapter.tenant_id == tenant.id)
        .where(Chapter.course_id == course_id).order_by(Chapter.number)
    ).all()
    rows = "".join(
        f"<li>Ch{c.number}: {_e(c.title)}</li>" for c in chapters
    ) or "<li>No chapters yet.</li>"
    form = (
        f"<form hx-post='/instructor/courses/{course_id}/chapters' hx-swap='none'>"
        f"<input name='number' type='number' min='1' required placeholder='Chapter #'>"
        f"<input name='title' required placeholder='Title'>"
        f"<textarea name='body_md' required placeholder='Markdown content'></textarea>"
        f"<button>Save chapter</button></form>"
    )
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8><title>Author {_e(course.title)}</title>"
        f"<script src='/static/htmx.min.js' defer></script></head>"
        f"<body><h1>Author: {_e(course.title)} ({_e(course.status)}, v{course.version})</h1>"
        f"<ul>{rows}</ul>{form}{_CSRF_JS}</body></html>"
    )


@router.post("/courses/{course_id}/chapters")
def author_upsert_chapter(
    course_id: UUID,
    request: Request,
    number: int = Form(...),
    title: str = Form(...),
    body_md: str = Form(...),
    part: str = Form(""),
    db: Session = Depends(get_db),
):
    """Create or update a chapter from markdown (finding #8)."""
    tenant = require_tenant(request)
    upsert_chapter(db, tenant_id=tenant.id, course_id=course_id, number=number,
                   title=title, body_md=body_md, part=part)
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
    db: Session = Depends(get_db),
):
    """Publish or unpublish a course (finding #8). Draft courses are hidden from learners."""
    tenant = require_tenant(request)
    if status_value not in ("draft", "published"):
        raise HTTPException(status_code=400, detail="invalid status")
    course = db.scalars(
        select(Course).where(Course.tenant_id == tenant.id).where(Course.id == course_id)
    ).first()
    if course is None:
        raise HTTPException(status_code=404)
    course.status = status_value
    if request.headers.get("HX-Request"):
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


_CSRF_JS = (
    "<script>document.body.addEventListener('htmx:configRequest',function(e){"
    "var m=document.cookie.match(/(?:^|;\\s*)csrf_token=([^;]+)/);"
    "if(m){e.detail.headers['x-csrf-token']=m[1];}});</script>"
)


@router.get("/grading", response_class=HTMLResponse)
def grading_queue(request: Request, db: Session = Depends(get_db)):
    """Manual grading queue: submissions awaiting a score (finding #4)."""
    tenant = require_tenant(request)
    rows = pending_grading(db, tenant_id=tenant.id)
    items = []
    for sub, act, email in rows:
        items.append(
            f"<li class='pending-item' data-submission='{sub.id}'>"
            f"<strong>{_e(act.title)}</strong> — {_e(email)} (attempt {sub.attempt_no})"
            f"<form hx-post='/instructor/scores/{sub.id}/override' hx-swap='none' "
            f"class='inline-grade'>"
            f"<input name='score_value' type='number' step='0.1' value='0' required>"
            f"<input name='max_score' type='number' step='0.1' value='10' required>"
            f"<input name='reason' value='manual grade' required>"
            f"<button>Save grade</button></form></li>"
        )
    body = "<ul>" + "".join(items) + "</ul>" if items else "<p>Nothing awaiting grading.</p>"
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8><title>Grading queue</title>"
        f"<script src='/static/htmx.min.js' defer></script></head>"
        f"<body><h1>Grading queue</h1>{body}{_CSRF_JS}</body></html>"
    )


@router.get("/dashboard/cohort/{cohort_id}", response_class=HTMLResponse)
def cohort_dashboard(cohort_id: UUID, request: Request, db: Session = Depends(get_db)):
    """Cohort progress + at-risk learners (finding #9)."""
    tenant = require_tenant(request)
    ov = cohort_overview(db, tenant_id=tenant.id, cohort_id=cohort_id)
    rows = "".join(
        f"<tr class='{'at-risk' if r['at_risk'] else ''}'>"
        f"<td>{_e(r['name'])}</td><td>{_e(r['email'])}</td>"
        f"<td>{round(100 * r['completion_pct'])}%</td>"
        f"<td>{'⚠ at risk' if r['at_risk'] else 'ok'}</td></tr>"
        for r in ov["rows"]
    )
    table = (f"<table><thead><tr><th>Name</th><th>Email</th><th>Completion</th>"
             f"<th>Status</th></tr></thead><tbody>{rows}</tbody></table>"
             if ov["rows"] else "<p>No learners enrolled.</p>")
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8><title>Cohort dashboard</title></head>"
        f"<body><h1>{_e(ov['cohort'].name)} — progress</h1>{table}</body></html>"
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
    rows = "".join(
        f"<tr><td>{_e(i['id'])}</td><td>{i['responses']}</td><td>{i['correct']}</td>"
        f"<td>{i['p_value']:.2f}</td></tr>"
        for i in items
    )
    table = (f"<table><thead><tr><th>Question</th><th>Responses</th><th>Correct</th>"
             f"<th>p-value</th></tr></thead><tbody>{rows}</tbody></table>"
             if items else "<p>No responses yet.</p>")
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8><title>Item analysis</title></head>"
        f"<body><h1>Item analysis — {_e(act.title)}</h1>{table}</body></html>"
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
