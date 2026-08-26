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
- [ADR 0009 — Academy-Owned Managed Application Lifecycle](docs/adr/0009-academy-owned-managed-application-lifecycle.md)
- [ADR 0010 — Academy-Local External Identity Authority](docs/adr/0010-academy-local-external-identity-authority.md)
- [ADR 0002 — Single-Academy Deployment](docs/adr/0002-single-academy-deployment.md)
- [ADR 0006 — Shared UI Contract](docs/adr/0006-adopt-shared-ui-contract.md)
- [Source-of-truth relationship map](docs/SOT_RELATIONSHIP_MAP.md)
- [Direct external-connector surface](docs/external-connector-surface.md) — the
  measured baselines the accepted Governance ratchet freezes
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
- Integrator can request only the product-owned `active`/`suspended` account
  transition and an exact external-subject binding through a signed, exact-plan
  lifecycle port. It cannot assign roles, enrolments, claims, names, email
  addresses, or credentials.

## Managed application lifecycle

Academy owns `academy.application.lifecycle.v1` and exposes the four typed
operations at `/api/v1/integrations/application-lifecycle/{plan,apply,observe,cancel}`.
The [canonical owner contract](docs/contracts/academy-application-lifecycle-v1.json)
is parseable by the kernel a68 capability grammar; the adjacent schema
directory holds eight self-contained canonical draft-2020-12 capability
input/output documents whose exact byte digests it pins. PLAN and APPLY inputs
are the Academy desired target itself; OBSERVE and CANCEL use exact subsets of
that declaration. Vendor/Integrator operation references, idempotency values,
approval metadata and plan/state digests are execution-envelope fields and are
absent. The documents are verified with kernel a68's
`CapabilitySchemaDocument`; that is checkout evidence until Academy can replace
its released a38 pin with a published a68-or-newer release.

The HTTP port is inert until `MANAGED_LIFECYCLE_INBOUND_HMAC_SECRET` is held by
the deployment. Requests use a separate exact-byte HMAC execution envelope
with a distinct key. PLAN persists an immutable target and expected-state
digest. APPLY accepts only those exact pins and is idempotent; the HTTP OBSERVE
and CANCEL adapters accept only the durable operation reference. That local
ledger envelope is not the product capability input.

ADR 0010 completes the external-login authority without joining application
databases: Academy owns its local exact binding and session-provenance rows,
while exact-pinned `dotmac-auth-oidc` 0.1.0a1 owns protocol verification only.
APPLY binds/enables the approved subject for `active` and retains it disabled
for `suspended`. The required `academy.external-identity.binding-ready` check
can be true only after migration 0055 and a complete deployment provider
registration. There is no shadow kernel table, email linking, provider role
mapping, or JIT account creation.

OIDC is enabled only when issuer, client id, client secret and redirect URL are
all present. The browser starts at `POST /login/oidc` and returns to
`GET /login/callback`; ceremony state is an opaque id backed by PostgreSQL and
atomically consumed across workers. Keep the callback URI exact at the IdP and
use HTTPS for every configured endpoint.

The product-owned
[`academy.identity-user-binding.v1`](docs/contracts/academy-identity-user-binding-v1.json)
composition permits only the issuer and immutable subject from the managed IdP
user APPLY receipt to enter `/external_subject/issuer` and
`/external_subject/subject`. `provider_binding` is
never copied from that receipt and must exactly match Academy's installed local
registration before APPLY mutates a binding.

## Local development

Requirements: Python 3.12 or 3.13, **Poetry 2.4.1**, Node.js 20, Docker, and
PostgreSQL client tools.

Poetry's version is pinned — in CI and on the production host alike — because
`poetry.lock` is only readable by the Poetry major that wrote it. An older
Poetry reports the mismatch as *"pyproject.toml changed significantly since
poetry.lock was last generated"*, blaming the repository for what is really a
toolchain problem; do not run `poetry lock` in response. Bump CI, the host, and
this line together or not at all.

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
