# LMS Buildout — Roadmap

Date: 2026-06-27
Branch: `feat/lms-buildout`

Addresses the 10 findings from the LMS readiness review. The work is decomposed
into 5 dependency-ordered slices. Each slice gets its own spec + plan + TDD
implementation, committed incrementally on this branch.

## Cross-cutting decisions (locked)

- **Data migration:** Backfill `CourseOffering`/links from existing discipline
  matches so no one loses access during the cutover.
- **Credentials:** Server-side **generated PDF certificates** (downloadable),
  plus a `CourseCompletion` record and badge status.
- **Authoring:** Draft/publish + version governance **and** an in-app markdown
  editor for chapters/activities (not just filesystem import).
- **Execution:** Incremental, single-threaded, TDD, review checkpoint between
  slices.

## Slices

1. **Entitlement foundation** (findings #1, #2) — `CourseOffering` model replaces
   discipline-string matching; enforce enrollment on every learn/lab/activity/
   submit route. *Spec: `2026-06-27-slice1-entitlement-design.md`.*
2. **Scheduling, pacing & completion** (findings #3, #5, #10) — dates/availability/
   prerequisites on offerings + activities; `CourseCompletion`; PDF certificates;
   lab governance by availability.
3. **Roster, invite & lifecycle** (findings #6, #7) — bulk enroll, invitations,
   roster states (waitlist/drop/transfer), password reset, email verification,
   suspension, learner profiles, self-service onboarding.
4. **Assessment policy** (finding #4) — attempt/time limits, randomized pools,
   feedback release rules, manual grading queue, rubric criteria, item analytics.
5. **Authoring + analytics** (findings #8, #9) — draft/publish + versioning +
   in-app editor; analytics events, at-risk learners, cohort trends, instructor
   dashboards, scheduled reporting.

## Progress log

- ✅ **Slice 1** (#1, #2) — CourseOffering + enforcement everywhere + backfill.
- ✅ **Slice 2** (#3, #5, part #10) — 2a offering window, 2b per-activity release/
  due, 2c completion records, 2d PDF certificates, 2e prerequisites.
- ✅ **Slice 3** (#6, #7) — core done: 3a roster bulk-enroll/drop (service+route),
  3b lifecycle service + public web pages (forgot/reset/accept-invite), 3c account
  suspension + instructor invite/suspend routes. **Tail items (optional polish):**
  email-verification flow (AccountToken `email_verify` kind already exists),
  learner-profile guardian/employer fields (Person.prefs JSONB available),
  self-service onboarding, transfer/waitlist UI.
- ⬜ **Slice 4** (#4) — assessment policy (attempts, time limits, randomized pools,
  manual grading queue, rubrics, item analytics). Not started.
- ⬜ **Slice 5** (#8, #9) — authoring (draft/publish + versioning + in-app editor)
  and analytics (events, at-risk, cohort trends, dashboards). Not started.

Migrations through `0014`. Test suite green except 7 pre-existing baseline
failures (platform_admin_token config + email-CLI db url) that fail on pristine
HEAD and are unrelated to this branch.

## Conventions (from the codebase)

- Models: `Base, TimestampMixin`, `uuid_pk()`, composite `(tenant_id, id)` unique
  constraints, composite tenant-scoped FKs.
- Migrations: Alembic; each new tenant-scoped table gets the `_rls(table)` helper
  (ENABLE+FORCE RLS, `*_tenant_isolation` policy on `app_current_tenant_id()`,
  GRANT to `app_user, platform_api`).
- Web auth: cookie sessions; `require_web_user`, `require_web_role(slug)` with
  `admin` as superset. No `db.commit()` inside handlers (get_db owns the tx).
- Tests: Postgres-only (RLS), `tenant_a`/`tenant_b` fixtures, `client_for`,
  `app_client`. Run with `poetry run pytest`.

## Note on alembic history

This branch adds `0008_course_offerings` chaining off `0007_person_profile`.
The main working tree has an *uncommitted* `0008_lab_instance_name_unique.py`
also chaining off `0007`. If both land, alembic will have two heads off `0007`
and need a merge revision. Resolve at integration time.
