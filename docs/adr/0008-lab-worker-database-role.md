# ADR 0008: Dedicated non-owning lab-worker database role

## Status

Accepted

## Decision

Continuous Academy lab workers and reconcilers connect as the exact role
`academy_lab_worker`. It is `LOGIN NOINHERIT BYPASSRLS NOSUPERUSER NOCREATEDB
NOCREATEROLE NOREPLICATION`, has no role memberships, owns neither the current
database nor any non-system schema or application relation (including
sequences), and receives
only the explicit runtime grants required by migrations 0055 and 0056.

Migration 0061 adds the learning consequences of a lab check: `SELECT` on
`courses`, `SELECT`/`INSERT` on `certificates`, and `SELECT` on
`course_completions`. Completion inserts are limited to `id`, `tenant_id`,
`person_id`, `course_id`, `status`, and `pct`; updates are limited to `status`,
`pct`, `completed_at`, and `updated_at`. The worker cannot update learner
identity, completion identity keys, or `erp_synced_at`, and receives no new
delete rights. Completion and certificate writers serialize on the completion
aggregate row, including concurrent first creation, without granting updates
on `people`. These consequences share the check's settlement transaction.

`app_admin` remains the schema-owning migration and offline-maintenance role;
it is not used by continuous worker processes.

## Bootstrap and rollback

CI creates `academy_lab_worker` before applying migration 0055 using the
test-only password in `scripts/initdb-roles.sql`, then migrations grant its
runtime privileges. Production bootstrap must likewise happen before applying
0055; migration application fails if the role is absent. Production bootstrap
is a separate operator-controlled procedure and is not executed by this
repository or its CI workflow. Password materialization is operator/OpenBao-
controlled and outside this change. The worker validates identity, safe role
attributes, memberships, BYPASSRLS, and non-ownership at connection time.

Rolling back 0056 revokes only grants introduced for `academy_lab_worker` and
leaves pre-existing `app_admin` migration/offline rights intact. Rolling back
0055 likewise removes the worker's queue grant while preserving `app_admin`'s
explicit migration grant.

Rolling back 0061 revokes only these added table and column grants.

## Consequences

The worker credential can bypass tenant RLS for its cross-tenant queue while
remaining unable to create or own schema objects. A role or ownership drift is
detected at startup rather than silently changing the worker's authority.
