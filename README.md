# Dotmac Academy

Dotmac Academy is Dotmac's single-instance admissions and learning application.
It covers public applications, entrance assessment, audited admissions review,
onboarding, courses, grading, labs, completion, certificates, and instructor
reporting.

Production accepts one configured Academy tenant. The inherited tenant-aware
schema and PostgreSQL Row-Level Security remain defence in depth; the product
does not expose public tenant provisioning or public account registration.

Architecture:

- [ADR 0007 — Academy Is a Kernel Product Assembly](docs/adr/0007-academy-is-a-kernel-assembly.md)
- [ADR 0008 — Kernel Identity and Migration-Lineage Cutover](docs/adr/0008-kernel-identity-and-lineage-cutover.md)
- [ADR 0002 — Single-Academy Deployment](docs/adr/0002-single-academy-deployment.md)
- [ADR 0006 — Shared UI Contract](docs/adr/0006-adopt-shared-ui-contract.md)
- [Source-of-truth relationship map](docs/SOT_RELATIONSHIP_MAP.md)
- [ADR 0001 — historical multi-tenant foundation](docs/adr/0001-multi-tenant-architecture.md)

## Security and ownership

- Academy management APIs require tenant-bound admin authentication.
- Accounts are created through admin invitations or accepted-applicant
  activation; `/auth/register` does not exist.
- Production declares `TENANCY=single`; the kernel binds host resolution to the
  sole tenant identity stored in the database.
- Applicant placement references an active cohort/track pair. Free-text
  `program` is display-only.
- Entrance-assessment time is derived from an explicit server-stamped start.
- Assessment writers use row locks and database uniqueness constraints.
- Domain transactions persist email intent to `email_outbox`; a timer handles
  SMTP retries after commit.
- Admissions transitions, placement corrections, resets, and reinvitations are
  recorded in the audit ledger.
- Browser responses carry CSP, clickjacking, MIME, referrer, permissions,
  cross-origin, and production HSTS headers.
- Repeated login failures produce a durable account lockout.

## Local development

Requirements: Python 3.12 or 3.13, Poetry, Node.js 20, Docker, and PostgreSQL
client tools.

```bash
poetry install
docker compose up -d db
poetry run alembic upgrade head
```

Bootstrap the one local Academy tenant and initial admin through the offline
command. Supply credentials through your shell or approved secret tooling; do
not write them into tracked files.

```bash
poetry run python -m app.cli bootstrap-tenant \
  --slug academy \
  --name "Dotmac Academy" \
  --admin-email admin@example.com \
  --admin-password '<local-password>'
```

Run the application:

```bash
poetry run uvicorn app.main:app --reload --port 8001 \
  --forwarded-allow-ips "127.0.0.1"
```

Use `http://academy.localhost:8001`. Browsers resolve `*.localhost`
automatically.

## Email delivery

Application requests queue email in the same transaction as the business
change. Drain committed intents with:

```bash
poetry run python -m app.cli email-outbox
```

Production should enable `deploy/academy-email-outbox.timer`. The worker uses
idempotency keys, stable message IDs, exponential retry, terminal failure
records, and a manual `--requeue-failed` repair path. CLI output reports counts
only and never prints tokenized links.

The settings page can send an immediate test email because that action is an
explicit transport diagnostic, not a domain consequence.

## Database roles

- `app_user`: request role with RLS enforced.
- `platform_api`: restricted settings-writer role retained under its historical
  name; it does not expose a tenant-provisioning API.
- `app_admin`: migration and offline maintenance role with `BYPASSRLS`; never
  used by request handlers.

`DATABASE_URL` uses `app_user`, `PLATFORM_DATABASE_URL` uses the restricted
settings writer, and `MIGRATION_DATABASE_URL` uses the offline migration role.

## Validation

Tests require a migrated disposable PostgreSQL database because SQLite cannot
exercise RLS or the concurrency constraints.

```bash
poetry run ruff check .
poetry run mypy --no-incremental
poetry run pip-audit
npm ci
npm run build:css
git diff --exit-code -- static/app.css
poetry run pytest -q
```

CI runs all gates. The CSS rebuild proves Academy still consumes the installed
`dotmac-ui` preset and that the committed browser asset is current. The
cross-tenant tests are deliberate RLS isolation
canaries even though production accepts only one Academy tenant.
