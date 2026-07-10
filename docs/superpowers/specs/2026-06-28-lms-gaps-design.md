# LMS Gaps — Standard-LMS Feature Closure (Design)

Date: 2026-06-28
Branch: `feat/lms-gaps` (off `feat/lms-buildout` @ `ad5ec4e`; merges back into the LMS line later)
Repo: `dotmac_academy_app`

## Goal

Close the standard-LMS gaps identified in the readiness review that are **not**
already on the `feat/lms-buildout` roadmap (so the two lines don't collide):
course discovery, communications, audit visibility, in-app notifications,
search, a learner calendar, richer content, more question types, and a weighted
gradebook.

**Explicitly out of scope** (owned elsewhere / deferred): Slice 4 remainder
(time limits, randomized pools, rubric criteria, feedback-release), Slice 5 #9
analytics, in-app authoring, the Slice 3 lifecycle tail — all owned by the active
`feat/lms-buildout` session. **SSO/MFA** deferred to a follow-up spec.
**Commercialization** (signup/billing/payments) out of scope per direction.
**SCORM/xAPI/LTI ingest and file uploads** deferred (integration-heavy; revisit
only if importing third-party courseware).

## Cross-cutting conventions (follow the codebase)

- Models: `Base, TimestampMixin`, `uuid_pk()`, `tenant_id` FK→tenants CASCADE
  (indexed), composite `(tenant_id, id)` unique + composite tenant-scoped FKs,
  RLS via the migration `_rls(table)` helper (ENABLE+FORCE, `*_tenant_isolation`
  policy on `app_current_tenant_id()`, GRANT to `app_user, platform_api`).
- Web: cookie sessions; `require_web_user`, `require_web_role(slug)` (admin =
  superset). NO `db.commit()` in handlers (get_db owns the tx). htmx forms so the
  global CSRF injector applies. Templates extend `base.html`; brand via
  `branding_name | default("Technical Academy")`.
- Entitlement (reuse, do not reinvent): `app/services/entitlements.py` —
  `accessible_course_ids(db, *, tenant_id, person_id)`,
  `person_can_access_course(...)`, `require_course_access(...)`,
  `open_course_ids(...)`, `unmet_prerequisites(...)`.
- New migrations start at `0020` (branch head is `0019_chapter_body_md`).
- Nav: `app/web/nav.py` `AREAS` drives sidebars (learn/teaching/admin).

## Feature 1 — Course catalog + Part-structured landing pages (Learn)

The entitlement model exists but there is no discovery UI (only the dashboard +
chapter reader). Add it on top of `entitlements`.

- Service `app/services/catalog.py`:
  - `my_courses(db, *, tenant_id, person_id) -> list[Course]` — Courses whose id
    ∈ `accessible_course_ids(...)`, ordered by title.
  - `all_courses(db, *, tenant_id) -> list[Course]` — every tenant course.
  - `course_completion(db, *, tenant_id, person_id, course_id) -> int` — passed
    activities / total, 0–100 (reuse `assessment.best_scores_for`).
  - `course_structure(db, *, tenant_id, person_id, course) -> dict` — chapters
    grouped by `Chapter.part` (ordered by `order_index, number`); each chapter →
    its activities with `{activity, passed, pct}`; plus `continue_target` (first
    unpassed) and `locked` flag from `unmet_prerequisites`.
- Router `app/web/catalog.py` (`require_web_user`):
  - `GET /courses` → `templates/learn/courses.html`: "My courses" cards
    (completion %); for instructor/admin also an "All courses" section.
  - `GET /courses/{slug}` → `templates/learn/course.html`: Part-grouped
    structure + Continue CTA + availability/prereq banner; access gated by
    `require_course_access` (staff bypass) — 403 otherwise; 404 unknown slug.
- Nav: add `{"label": "Courses", "path": "/courses"}` to the **learn** sidebar
  after Home.
- Tests: my-courses vs all-courses by role; landing Part grouping + pass/lock;
  non-enrolled student 403; unknown slug 404.

## Feature 2 — Learner calendar / agenda (Learn)

Offerings carry `starts_at/ends_at`; per-activity pacing carries `due_at`. Surface
them as a forward agenda (no month-grid — YAGNI).

- Service `app/services/agenda.py`:
  - `upcoming_for_person(db, *, tenant_id, person_id, limit=50) -> list[dict]` —
    merged, date-sorted items across the person's accessible courses: offering
    window open/close events and activity `due_at` deadlines, each
    `{when, kind, title, course, link}`. Past items excluded (or a small recent
    window); only accessible courses.
- Router: add `GET /calendar` to `app/web/catalog.py` →
  `templates/learn/calendar.html` (agenda list grouped by day).
- Nav: add `{"label": "Calendar", "path": "/calendar"}` to learn sidebar.
- Tests: a due_at in the future appears; an item in a non-accessible course does
  not; ordering is chronological.

## Feature 3 — Content search (global)

- Service `app/services/search.py`:
  - `search(db, *, tenant_id, person_id, q, is_staff) -> dict` with `courses`
    and `chapters` hits. Scope: `q` ILIKE over `Course.title` and
    `Chapter.title`/`Chapter.body_html`, restricted to accessible courses
    (`accessible_course_ids`) for non-staff, all tenant courses for staff. Cap
    results (e.g. 20 each). Empty/whitespace `q` → empty result.
- Router: `GET /search?q=` in a small `app/web/search.py` →
  `templates/search.html` (grouped results linking to course landing / chapter).
- UI: a search box in `templates/shell/_topbar.html` (GET form to `/search`).
- Tests: hit in an accessible course returns; hit in a non-accessible course is
  excluded for a student but returned for staff; blank query empty.

## Feature 4 — Announcements

- Model `app/models/announcement.py::Announcement` — `tenant_id`, `cohort_id`
  (nullable: NULL = tenant-wide), `author_person_id`, `title String(200)`,
  `body_md Text`, `body_html Text` (rendered via `authoring.render_markdown`),
  timestamps. RLS. Composite FK `(tenant_id, cohort_id)`→cohorts (nullable FK ok).
  Migration `0020_announcements`.
- Service `app/services/announcements.py`:
  - `create(db, *, tenant_id, author_person_id, title, body_md, cohort_id=None)`.
  - `for_person(db, *, tenant_id, person_id, limit=20)` — tenant-wide
    (`cohort_id IS NULL`) OR targeting a cohort the person is actively enrolled
    in; newest first.
  - `list_for_tenant(...)` / `delete(...)` for management.
  - On create, emit notifications (Feature 5) to the audience and a
    `write_audit_event(action="announcement.created", ...)`.
- Routers:
  - Manage (instructor/admin) in `app/web/teaching.py` or a new
    `app/web/announcements.py`: `GET/POST /instructor/announcements` (list +
    create form: title, body_md, optional cohort) + `POST
    /instructor/announcements/{id}/delete`.
  - Read (learners): `GET /announcements` → list; latest 3 also surfaced on the
    Learn Home (`learn.home`).
- Nav: learn sidebar "Announcements" (`/announcements`); teaching sidebar
  "Announcements" (`/instructor/announcements`).
- Tests: tenant-wide announcement visible to all; cohort-targeted visible only to
  that cohort's members; create requires instructor/admin (student 403); RLS
  isolation.

## Feature 5 — In-app notifications center

- Model `app/models/notification.py::Notification` — `tenant_id`, `person_id`,
  `kind String(40)`, `title String(200)`, `body Text`, `link String(255) null`,
  `read_at DateTime null`, timestamps. RLS. Migration `0021_notifications`.
- Service `app/services/notifications.py`:
  - `notify(db, *, tenant_id, person_id, kind, title, body="", link=None)`.
  - `notify_many(db, *, tenant_id, person_ids, ...)`.
  - `unread_count(db, *, tenant_id, person_id) -> int`.
  - `recent(db, *, tenant_id, person_id, limit=30)`.
  - `mark_all_read(db, *, tenant_id, person_id)`.
- Wiring (minimal, best-effort, never break the triggering action):
  - announcement.create → `notify_many` to the audience (Feature 4).
  - first passing score (`email.notify_score_if_first_pass` path) → also
    `notify(kind="result", link=/courses/...)`.
  - certificate issued (`certificates.issue_certificate`) → `notify(kind="certificate")`.
- Router: `GET /notifications` (list + "mark all read" POST) in a new
  `app/web/notifications.py`. Unread badge rendered in `_topbar.html` via the
  nav context (add `unread_notifications` to `context.nav_context`).
- Nav/topbar: a bell with unread count linking to `/notifications`.
- Tests: notify creates a row; unread_count; mark_all_read zeroes it; a
  notification for person A is not visible to person B (RLS); badge count in
  context.

## Feature 6 — Audit-log viewer (Admin)

`AuditEvent` + `write_audit_event` already exist; add the read UI.

- Service: extend `app/services/audit.py` with
  `list_events(db, *, tenant_id, limit=100, offset=0, action=None, actor_person_id=None) -> list[AuditEvent]`
  (newest first, optional filters).
- Router: `GET /admin/audit` (admin-only, platform-token NOT required — distinct
  from settings) → `templates/admin/audit.html`: table (time, actor email,
  action, entity_type, entity_id, details) with simple action/actor filters +
  pagination (limit/offset querystring). Resolve actor emails via a People join.
- Nav: add "Audit" to the **admin** sidebar after Users.
- Tests: admin sees events; student/instructor 403; filter by action narrows;
  events are tenant-scoped (RLS — another tenant's events absent).

## Feature 7 — Rich content embeds in chapters

Extend the markdown renderer so authored chapters can include video and files,
with sanitization (the branch recently fixed an XSS issue — keep output safe).

- In `app/services/authoring.py::render_markdown` (and the import renderer if
  separate), add a post-render transform `embed_media(html) -> html`:
  - Bare links ending `.mp4/.webm/.ogg` → `<video controls>` (self-hosted).
  - `youtube.com/watch?v=ID`, `youtu.be/ID`, `vimeo.com/ID` links → a
    **whitelisted** responsive `<iframe>` (only these hosts; ID validated by
    regex; nothing else templated into the iframe).
  - Links to common doc extensions (`.pdf/.zip/.csv/.pcap/...`) → a styled
    download link with an icon.
  - Everything else passes through the existing sanitizer unchanged.
- No new model (uses existing chapter body). File **uploads** remain out of scope
  (link to externally-hosted assets / existing `static/figures`).
- Tests: a youtube link renders a single whitelisted iframe (no script, correct
  host); a `.mp4` link renders `<video>`; a `javascript:`/arbitrary-host iframe
  attempt is NOT produced; ordinary links/markdown unaffected.

## Feature 8 — Additional question types

Today: `single | multi | truefalse` (all MCQ). Add two auto-gradable types.

- `numeric` — `correct` holds a target; optional tolerance in the question
  payload (`options: {"tolerance": x}`); graded as |answer−target| ≤ tolerance.
- `short_text` — `correct` holds accepted answers (list); graded
  case-insensitively, trimmed; optional `options: {"regex": true}` to match any
  accepted pattern.
- Changes:
  - `app/services/assessment.py::grade_submission` — branch on `question.type`
    for `numeric`/`short_text` (existing set-equality logic stays for MCQ).
  - `app/services/bank_loader.py` — accept + validate the new types (numeric
    needs a parseable target; short_text needs ≥1 accepted answer).
  - Take-test template (`templates/learn/activity.html`) — render a number input
    / text input for the new types; submit handler already posts `answers` dict.
- No migration (`Question.type` is a free string; payload lives in existing
  JSONB `options`/`correct`).
- Tests: numeric within/outside tolerance; short_text case-insensitive match +
  non-match; a mixed bank grades correctly; bank_loader rejects malformed.

## Feature 9 — Weighted gradebook

Today reporting is pass/fail per activity. Add weighting + a gradebook grid.

- Migration `0022_activity_weight`: add `activities.weight FLOAT NOT NULL DEFAULT
  1.0`; model `Activity.weight`.
- Service `app/services/gradebook.py`:
  - `course_grade(db, *, tenant_id, person_id, course_id) -> dict` — weighted
    score = Σ(best.fraction × weight) / Σ(weight) over the course's activities
    (best score per activity; missing = 0), returns `{pct, per_activity}`.
  - `cohort_gradebook(db, *, tenant_id, cohort_id) -> dict` — students ×
    activities grid of best %s + each student's weighted course grade
    (reuse `reports` cohort helpers for membership/activities).
- Router: `GET /instructor/gradebook/{cohort_id}` (instructor/admin) →
  `templates/instructor/gradebook.html` (grid: rows=students, cols=activities
  with weights, final weighted column) + CSV export
  `GET /instructor/gradebook/{cohort_id}.csv`.
- Nav: add "Gradebook" to the **teaching** sidebar (after Reports).
- Tests: weighted average correct (e.g., weights 1 and 3 → 25/75 blend); missing
  submission counts as 0; CSV columns/rows; instructor/admin only.

## Build order (subagent loop; review each)

Independent-first, then the ones that feed others:
1. **Catalog + landing** (Feature 1) — reuses entitlements; highest-visibility.
2. **Calendar/agenda** (Feature 2).
3. **Search** (Feature 3).
4. **Audit viewer** (Feature 6) — independent, reads existing events.
5. **Notifications center** (Feature 5) — model + service + topbar badge.
6. **Announcements** (Feature 4) — emits notifications (needs Feature 5).
7. **Rich embeds** (Feature 7).
8. **Question types** (Feature 8).
9. **Weighted gradebook** (Feature 9).
10. **Integration**: full suite green on `academy_gaps`; ruff+mypy clean (the
    branch enforces both in CI); nav cross-check.

Each feature = its own plan slice executed via subagent-driven-development with
per-task review; commit per task; migrations applied to `academy_gaps`.

## Testing baseline

Postgres on `dotmac_academy_app-db-1` :5437, dedicated DB **`academy_gaps`**
(migrated to branch head). Poetry venv py3.12. Export `TEST_DATABASE_URL`/
`TEST_MIGRATION_DATABASE_URL`/`DATABASE_URL`/`MIGRATION_DATABASE_URL` →
`academy_gaps`, `PLATFORM_ROOT_DOMAIN=localhost`. Refresh grants
(`GRANT app_user,platform_api TO app_admin` + table/sequence grants) after each
new migration.
