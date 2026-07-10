# dotmac_starter_mt

Multi-tenant FastAPI starter. Tenant isolation enforced at three layers:

1. **Routing** — subdomain resolves to a tenant before any request handler runs.
2. **Application** — every service receives `tenant_id` via request state.
3. **Database** — PostgreSQL Row-Level Security policies fail closed if app code forgets to filter.

See [`docs/adr/0001-multi-tenant-architecture.md`](docs/adr/0001-multi-tenant-architecture.md)
for the full design.

## What's in this skeleton

- `Tenant` model + `tenant_domains` for custom domain support.
- `Person` model with `tenant_id` and per-tenant unique email.
- Minimal JWT auth with tenant-bound credentials and sessions.
- Minimal RBAC with tenant-scoped roles, role grants, and audit events.
- CSRF middleware, tenant-aware in-memory rate limiting, and request IDs.
- `TenantResolverMiddleware` that parses host header → `request.state.tenant`.
- `get_db` dependency that runs `SET LOCAL app.current_tenant` for RLS.
- Initial Alembic migration that creates `app_user`, `platform_api`, and `app_admin`
  Postgres roles, applies RLS policies, and seeds the schema.
- Cross-tenant isolation tests as canaries.

## What's NOT here yet

This is intentionally minimal. To productionize, port from `dotmac_starter`:

- MFA, password reset, account lockout, and production auth hardening
- Billing, file uploads, notifications, scheduler
- Security headers
- Frontend (Tailwind, Alpine CSP build, templates)
- CI workflows
- Production Dockerfile / compose

Each port follows the same pattern: add `tenant_id`, write the cross-tenant isolation test
first, port the code, watch the test go green.

## Quickstart (dev)

```bash
poetry install
docker compose up -d db
poetry run alembic upgrade head
poetry run uvicorn app.main:app --reload --port 8001 \
    --forwarded-allow-ips "127.0.0.1"
```

In dev, browsers resolve `*.localhost` automatically:

```bash
# Provision two tenants (as platform admin)
curl -X POST http://localhost:8001/platform/tenants \
    -H "Content-Type: application/json" \
    -d '{"slug":"acme","name":"ACME"}'
curl -X POST http://localhost:8001/platform/tenants \
    -H "Content-Type: application/json" \
    -d '{"slug":"widgets","name":"Widgets Inc"}'

# Same Person endpoint, different tenants
curl -X POST http://acme.localhost:8001/people \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@acme.com","first_name":"Alice","last_name":"A"}'
curl http://acme.localhost:8001/people     # sees Alice
curl http://widgets.localhost:8001/people  # sees nothing
```

## Run the cross-tenant tests

```bash
poetry run pytest \
    tests/test_cross_tenant_isolation.py \
    tests/test_auth_tenant_claim.py \
    tests/test_rbac_audit_isolation.py \
    tests/test_security_middleware.py \
    -v
```

These tests require a migrated disposable Postgres database because SQLite cannot enforce
RLS.

## DB roles

```
app_user      — Tenant request role. RLS-enforced. Sets app.current_tenant per request.
platform_api  — Online platform routes. Explicit grants, no RLS bypass.
app_admin     — Alembic migrations and offline maintenance only. Bypasses RLS.
```

The `DATABASE_URL` env var should use `app_user`. `PLATFORM_DATABASE_URL` should use
`platform_api`. Migrations use `MIGRATION_DATABASE_URL` connecting as `app_admin`.
Settings are loaded from the environment and from a local `.env` file.

## Middleware Notes

- Rate limiting is process-local in this skeleton. It is keyed by
  `tenant_id/client_ip/path`, but it does not aggregate across Gunicorn workers and keys live for the
  process lifetime. Port the same key shape to Redis with TTLs for production.
- Inbound `X-Request-ID` is ignored by default to prevent log poisoning. Set
  `TRUST_INBOUND_REQUEST_ID=true` only behind a trusted proxy that normalizes that header.
- CSRF uses a double-submit cookie/header check. Origin/Referer validation is deferred; add it before
  relying on browser-cookie auth in production.

## License

TBD.
