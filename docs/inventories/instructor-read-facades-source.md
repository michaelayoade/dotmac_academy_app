# Instructor read facades — source candidate, 2026-10-19

Academy owns presentation only. `analytics.item_analysis` maps public Learning
`ItemAnalysis` facts to the historical item keys. `dashboards.cohort_overview`
uses `legacy_cohort_overview`, preserving completion means, ordered canonical
people, course-scoped activity and strict risk/window comparisons. Default policy
comes from the existing strict Settings store keys
`learning_instructor_at_risk_fraction` and `learning_instructor_stale_days`;
explicit service overrides remain supported, including zero. The separate
`insight_cohort_overview` policy is not used here.

`lookups.cohort_or_404` maps the new public Learning
`instructor_cohort_by_id` detached point result to Academy NotFoundError. Learning
owns the single tenant/id-constrained indexed query and its existing ReportCohort
projection. Academy adds no ORM query, canonical identity join or write path.

All 428 parent files, modes and existing tests are unchanged. In particular the
actual instructor route signatures, template context keys, grade thresholds,
role policies and lifecycle writer bytes are conserved. The missing
`app.services.lifecycle` remains a separate unresolved authority-bound writer gap;
this candidate does not establish whole-factory import closure.

Restored exact bytes and modes from the pinned historical e0ef snapshot:
- `templates/instructor/dashboard_cohort.html`: exact historical path.
- `templates/instructor/item_analytics.html`: exact historical path.
Their existing `base.html`, shell includes and static dependencies are already
present; no existing template or asset was overwritten.

Historical `tests/services/test_analytics.py` and `test_dashboards.py` were ported
as new `test_analytics_owner.py` and `test_dashboards_owner.py`. Every historical
assertion is retained; legacy Person construction is replaced by the existing
explicit canonical Party/PartyPerson fixture helper `_person` from
`test_reports_owner.py`. There is no Person compatibility shim.

New hosted canaries exercise real Learning best-score/item facts, completion
means including missing offered courses, canonical people without account-profile
filtering, unrelated-course inactivity exclusion, custom stored thresholds and
windows, boundary equality, explicit zero overrides, tenant/missing 404s,
unchanged route template contexts/rendered bodies and caller transaction/read-only
behavior. They have NOT RUN. Whole factory closure, installed canonical owners,
a004 physical FK compatibility and a genuine hosted app_user database remain
prerequisites. The paired Learning successor adds its own genuine point-read
single-SELECT/tenant/immutable-DTO/caller-transaction canary.

Learning successor and required Kernel V3 are UNALLOCATED/UNRELEASED source
inputs. Existing released artifacts do not provide qualification of future APIs.
No local application import, runtime, tests, SQL execution, build, installation,
Docker or network shell command was performed. Validation is stdlib AST/hash
and the pinned Ruff binary on changed/new Python source only.
