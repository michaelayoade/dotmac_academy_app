# ADR 0010: Scoped facilitator nominations are gated assignments

Status: Accepted

## Context

Academy historically represented cohort facilitators by changing an
`Enrollment.role_in_cohort` value to `instructor`. That makes a learner's
enrollment role compete with a teaching assignment and can erase the learner
track relationship even though learner progress and facilitator eligibility
are separate facts.

Academy currently has one canonical completion fact at course granularity:
`CourseCompletion(tenant_id, person_id, course_id)` with
`status='completed'`. It has no offering-specific or cohort-specific completion
record. `CourseOffering` is the canonical link from a cohort to a course.

## Decision

Facilitation is a separate tenant-scoped aggregate with a
`pending -> active -> revoked` lifecycle. A nomination targets exactly one
active course offering or one cohort. Any active tenant `Person` can be
nominated; nomination does not rewrite `Enrollment`, track, progress, or grant
the global instructor `PersonRole`.

A course nomination snapshots the offering's course as its one requirement. A
cohort nomination snapshots the distinct courses from all active offerings in
that cohort. Later offering changes do not silently change an existing
nomination's eligibility contract. A cohort with no active offerings remains
pending because an empty requirement set is not evidence of eligibility.
The same snapshot also bounds authorization: adding a new course to the
cohort does not silently widen an existing facilitator's teaching access.

Eligibility means that the nominated person has a canonical
`CourseCompletion.status == 'completed'` row for every snapshotted course. This
is deliberately course-level: the present model cannot prove that a completion
occurred in the nominated offering or cohort. Already eligible nominees become
active in the nomination transaction. Otherwise, they remain pending and an
idempotent row-locked reconciliation or sweep activates them after the missing
completion facts appear.

The canonical completion writer reconciles affected nominations in the same
transaction for immediate activation. The scheduled reminder sweep also runs
an eligibility-filtered reconciliation as the repair path; incomplete older
nominations cannot starve later eligible nominations.

Nomination and activation each create an in-app notification in the same
transaction as the aggregate change. The service flushes but never commits or
rolls back; the calling adapter owns the session transaction. Repeated
nomination, reconciliation, sweep, and revocation calls do not duplicate
lifecycle transitions or their notifications.

Migration 0064 backfills each active legacy instructor `Enrollment` whose
person also holds the legacy instructor `PersonRole` as an active,
cohort-scoped assignment with reason `legacy_grandfathered`. Requiring both
facts preserves pre-migration authorization and does not promote orphaned drift
that the old role gate refused. The legacy row is retained unchanged so
migration does not destroy enrollment evidence or learner state. These
grandfathered assignments intentionally have no completion requirements; all
new or re-opened nominations use the gated policy.

## Consequences

- Facilitator authorization must read active scoped assignments, not infer new
  assignments from `Enrollment.role_in_cohort` or global `PersonRole`.
- Assessment rows do not carry offering provenance. Course-only assignments
  therefore fail closed on assessment access, and cohort assignments exclude
  learners whose shared-course submission is ambiguous across authorized and
  unauthorized offerings.
- Course deletion cannot silently erase a snapshotted requirement; the
  requirement reference is restrictive while nomination deletion cascades its
  requirements.
- The two tables use forced tenant RLS and tenant-composite foreign keys. Their
  partial unique indexes provide one lifecycle aggregate per person and scope.
- An architecture test forbids restoring an application writer that creates
  or mutates an instructor-role `Enrollment`.
- A future offering-specific completion model would require a new migration and
  eligibility contract; it must not be inferred from the current course-level
  record.
