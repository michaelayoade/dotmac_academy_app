# Slice 2 — Scheduling, Pacing & Completion

Date: 2026-06-27
Findings: **#3** (no scheduling/pacing), **#5** (shallow completion/no credential),
**#10** (labs ungoverned by course policy).

Built in committable sub-increments on top of Slice 1's `CourseOffering`.

## 2a — Offering scheduling window  ✅ first

Add `starts_at`, `ends_at` (nullable `timestamptz`) to `course_offerings`.
Availability: an offering is *open* iff `(starts_at is null or now >= starts_at)`
and `(ends_at is null or now <= ends_at)`. Null window = always open (so all
Slice 1 behaviour is preserved).

- `entitlements.open_course_ids(db, *, tenant_id, person_id, now)` — entitled
  courses whose offering is currently open.
- `entitlements.require_course_open(db, *, tenant_id, person_id, course_id, now)`
  — 403 if not entitled OR outside the window.
- Learner activity routes (chapter/activity/submit) and lab routes
  (detail/launch) switch from `require_course_access` to `require_course_open`.
- Dashboard keeps listing via `accessible_course_ids` (entitlement), so future/
  past offerings still appear — with an availability status badge.

## 2b — Per-activity release/due dates

`offering_activities(offering_id, activity_id, release_at, due_at)` — optional
per-offering overrides. No row ⇒ activity follows the offering window. `release_at`
in the future blocks open/submit; past `due_at` blocks *submit* but still allows
read (late policy out of scope). Powers "week 3 opens Monday / quiz due Friday".

## 2c — Completion records

`course_completions(tenant_id, person_id, course_id, offering_id, status,
completed_at, pct)` where status ∈ {in_progress, completed}. A service computes
completion from passing best-scores over required activities and upserts the
record. Transcript gains a course-level completion row + required-but-missing
status (vs only scored rows today).

## 2d — PDF certificates

On `completed`, a certificate is issuable. `GET /learn/certificates/{course_id}`
renders an HTML certificate then streams a generated PDF (WeasyPrint). A
`certificates` record stores serial + issued_at for verification.

## 2e — Prerequisites

`course_prerequisites(course_id, requires_course_id)`; access to a course
requires the prerequisite course completed. Enforced in `require_course_open`.

## Testing

Postgres `tenant_a`/`tenant_b`. Time handled with explicit `now` params (no
wall-clock coupling): pass `now` into the service/helpers; routes use
`datetime.now(UTC)`.
