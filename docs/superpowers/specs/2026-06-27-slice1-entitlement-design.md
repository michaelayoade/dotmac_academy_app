# Slice 1 — Entitlement Foundation

Date: 2026-06-27
Findings addressed: **#1** (course entitlement not enforced on chapter/activity/
submit routes) and **#2** (no explicit course-offering model; access leaks across
a discipline).

## Problem

Today a cohort is linked to courses only by a shared `discipline` string
(`learn.py:_enrolled_courses`, `reports.py:_cohort_activities`). Two consequences:

1. **Broken access control.** The dashboard filters by discipline, but
   `chapter` (`learn.py:155`), `activity` (`191`), and `submit` (`216`) do *not*
   re-check entitlement. A student who knows a slug/UUID can read and submit any
   course's activity in the same tenant.
2. **Over-broad grants.** Enrolling in one cohort grants access (and reporting)
   to *every* course sharing that discipline.

## Design

### Model: `CourseOffering`

One table is the explicit cohort↔course link now, and the anchor for scheduling
columns in Slice 2.

```
app/models/offering.py
  class CourseOffering(Base, TimestampMixin):
    __tablename__ = "course_offerings"
    id           uuid_pk
    tenant_id    FK tenants.id (CASCADE), indexed
    cohort_id    uuid, indexed
    course_id    uuid, indexed
    status       String(20) default "active"   # active | archived
    __table_args__:
      UniqueConstraint(tenant_id, id)                         # for composite FKs
      UniqueConstraint(tenant_id, cohort_id, course_id)       # one link per pair
      FK (tenant_id, cohort_id) -> cohorts(tenant_id, id) CASCADE
      FK (tenant_id, course_id) -> courses(tenant_id, id) CASCADE
```

### Migration: `0008_course_offerings`

`down_revision = "0007_person_profile"`.

1. `create_table("course_offerings", ...)` + indexes + `_rls("course_offerings")`.
2. **Backfill** (preserve current access): for each cohort, insert one offering
   per course whose `discipline` matches the cohort's `discipline`. Implemented
   as a single SQL `INSERT ... SELECT` so it runs under the migration role
   (RLS-bypassing `app_admin`); tenant scoping is carried by joining on
   `tenant_id`:

   ```sql
   INSERT INTO course_offerings (id, tenant_id, cohort_id, course_id, status,
                                 created_at, updated_at)
   SELECT gen_random_uuid(), c.tenant_id, c.id, co.id, 'active', now(), now()
   FROM cohorts c
   JOIN courses co
     ON co.tenant_id = c.tenant_id AND co.discipline = c.discipline;
   ```

   (`gen_random_uuid()` from pgcrypto; the initial migration already relies on
   Postgres UUID support — verify the function is available, else use
   `uuid_generate_v4()` / application-side ids.)

`downgrade`: drop table (RLS/policy dropped with it).

### Service: `app/services/entitlements.py`

Pure, reusable, tenant-scoped helpers (no HTTP concerns except the one raiser):

```python
def accessible_course_ids(db, *, tenant_id, person_id) -> set[UUID]:
    """Course ids the person may access: active Enrollment -> Cohort ->
    active CourseOffering -> Course."""

def person_can_access_course(db, *, tenant_id, person_id, course_id) -> bool

def require_course_access(db, *, tenant_id, person_id, course_id) -> None:
    """Raise HTTPException(403) if not entitled."""
```

Query joins `Enrollment` (status='active', role student) → `CourseOffering`
(status='active') on `cohort_id`, returns distinct `course_id`s.

### Enforcement wiring

- `learn.py`
  - `_enrolled_courses` → return courses whose id ∈ `accessible_course_ids(...)`
    (drop the discipline query entirely).
  - `chapter` (155): after loading `course`, `require_course_access(course.id)`.
  - `activity` (191): after loading `act`, `require_course_access(act.course_id)`.
  - `submit` (216): same guard before grading.
  - `progress` (255): iterate accessible courses only (not all tenant courses).
- `labs.py:176`: resolve the lab's `course_id`; if the lab is course-bound,
  `require_course_access`. (Confirm lab→course linkage when implementing; if a
  lab has no course, leave existing behaviour.)
- `reports.py`: `_cohort_activities` keys off the cohort's offerings
  (course_ids = courses linked via `course_offerings` for that cohort) instead of
  discipline. `cohort_matrix`/`student_transcript` otherwise unchanged.

### Authorization status code

`403 Forbidden` for an in-tenant course the person isn't entitled to. Rationale:
semantically correct, matches existing `require_web_role` (403), and the course
catalog is not a secret within a tenant. (404 was considered to hide existence;
rejected.)

## Testing (TDD, Postgres `tenant_a`/`tenant_b`)

New `tests/web/test_entitlements.py` (+ a migration/backfill test):

1. **Enrolled happy path** — student in cohort with an offering for course A:
   `GET /courses/A/chapters/1` → 200; `GET /activities/{a}` → 200;
   `POST /activities/{a}/submit` → 200.
2. **Finding #1 regression** — student NOT enrolled for course B (valid slug +
   activity UUID): chapter → 403, activity GET → 403, submit POST → 403, and
   **no Submission/Score row is written**.
3. **Finding #2 regression** — course shares the cohort's discipline but has *no*
   offering: not accessible (proves discipline matching no longer grants access).
4. **Dashboard** — `/` lists only offered courses; `progress` only accessible.
5. **Reports** — `cohort_matrix` columns come from the cohort's offerings.
6. **Backfill** — after migration, a cohort + same-discipline course yields an
   offering row; access preserved.

A test helper seeds: person + credential + cohort + enrollment + course +
chapter + bank + question + activity + offering, reusing existing fixture
patterns.

## Out of scope (later slices)

Dates/availability/prerequisites (Slice 2), instructor CRUD for offerings UI
(Slice 3 roster work touches it), attempt limits (Slice 4). Slice 1 adds the
model, the backfill, and the enforcement only.
