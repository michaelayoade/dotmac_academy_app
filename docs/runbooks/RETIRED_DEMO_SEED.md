# Retired Academy demo seed

`scripts/seed_academy_demo.py` is a retired compatibility entrypoint. Running it
directly or as `python -m scripts.seed_academy_demo` exits with status 2 and
instructions. Importing it is inert. It does not load application configuration,
read `SEED_ADMIN_PASSWORD`, connect to a database, or create/update any data.
Supplying a password or other arguments does not enable it.

## Why it was retired

The historical demo script directly wrote identity, credential, role-grant,
cohort, enrollment, course, chapter, offering, bank, question, and activity data.
Changing its imports to canonical model facades would retain those displaced
writers. The executable writer and embedded demo content have therefore been
removed, including the password resolver and SQL helper.

A bounded source-reference audit found no workflow or runtime callers; the
remaining references were the historical runtime-readiness inventory,
architecture guard, and former password-helper tests. This is source evidence,
not a claim that every external operator command has been inventoried. Old
operator commands now receive an explicit refusal. Historical inventory entries
remain historical evidence.

## Supported replacement workflow

There is no replacement one-command demo fixture. Build the required scenario
explicitly through the current product workflows, with an authorized operator:

1. For a new tenant, inspect `python -m app.cli bootstrap-tenant --help` and use
   that canonical bootstrap command under the configured bootstrap policy. The
   empty `BOOTSTRAP_ALLOWED_DATABASE_ROLE_PAIRS` default denies bootstrap; actual
   database privileges and tenant policies are also required. Existing tenants
   should use their current administrator rather than bootstrap again.
2. Use Admin **Users** (`/admin/users`) for accounts, invitations, and role
   management. Use instructor **Cohorts** (`/instructor/cohorts`) for cohorts and
   enrollment, and **Course content** (`/instructor/courses`) for course/chapter
   authoring and the associated teaching workflows.
3. Where an approved manual import is appropriate, inspect
   `python -m app.cli import-manual --help` (or `import-foundation --help` for
   Foundation content) rather than restoring the old embedded demo chapters.
4. For question content, use the course's bank-draft UI or inspect
   `python -m app.cli import-banks-as-draft --help` (alias: `load-banks`). This
   imports YAML as unpublished drafts. It does not publish, overwrite UI drafts,
   repoint activities or entrance defaults, or create activities. Repair and lint
   drafts in the current course bank workflow.

Command names and draft-import behavior above are verified against `app/cli.py`;
UI entry routes are defined in `app/web/accounts.py` and `app/web/instructor.py`.
These workflows provide the functional pieces, not identical historical demo
rows, automatic fixtures, or a snapshot-restore bypass.

## Boundaries still in force

This retirement is source-only. It does not alter an existing tenant, grant an
operator database authority, qualify a deployment, or establish full Learning
cutover. Real bank publish/repoint journeys and their production gates remain
pending; draft import is the safe scope described here. Existing publish,
repoint, entrance-default, migration, and production authorization gates must
still be satisfied separately. Do not use this runbook as approval to publish a
bank, repoint an activity, or modify production.
