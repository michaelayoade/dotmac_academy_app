# ADR 0001 — Multi-Tenant Architecture

**Status:** Accepted
**Date:** 2026-05-04
**Supersedes:** N/A
**Successor of:** None — this is the founding decision for `dotmac_starter_mt`.

## Context

`dotmac_starter` is a single-tenant FastAPI starter. Multiple downstream products need
multi-tenant isolation as a core invariant. Retrofitting the existing starter would mean
every model, query, dep, and test has to be rewritten — and a single missed `WHERE` clause
becomes a cross-tenant data leak. This ADR pins the architecture for a clean-slate
multi-tenant starter.

The non-goal is feature parity with `dotmac_starter`. The goal is **isolation as a
load-bearing structural property**, not an opt-in filter.

## Foundational Decisions

### D1. Identity model: tenant-local `Person`

Each tenant has its own `people` rows. The same email can exist in two different tenants
as two distinct people. There is **no global identity record** that spans tenants.

**Rationale.** 80% of B2B SaaS doesn't need cross-tenant identity. Tenant-local Person:

- Removes the "which tenant am I logging into?" UX problem entirely.
- Lets us enforce email uniqueness per-tenant via a simple composite unique constraint.
- Means the JWT `sub` claim plus `tenant_id` claim uniquely identify the actor.
- Lets a person delete their account in tenant A without affecting their account in tenant B.

**What this rules out.** Single sign-on across multiple tenants without a separate
identity provider. If you need that, you bolt on an external IdP (Auth0, Keycloak) and
keep `Person` tenant-local — the IdP becomes the global identity, `Person` becomes the
per-tenant projection.

**Upgrade path if we change our mind.** Add `Identity` table with `(email, hashed_password)`,
add `Person.identity_id`, allow `Identity` → many `Person`. Migration is mechanical.
Not free, but not catastrophic.

### D2. Tenant routing: subdomain

Production: `acme.app.com`, `widgets.app.com`, with a wildcard TLS cert (`*.app.com`)
plus optional custom-domain support per tenant (CNAME to `app.com`, ACME on demand).
Dev: `acme.localhost:8001`, `widgets.localhost:8001` (browsers resolve `*.localhost`
without `/etc/hosts` changes).

**Rationale.** Subdomain wins over path-prefix and header-based routing because:

- **Cookies are tenant-scoped automatically.** A session cookie set on `acme.app.com`
  cannot be sent to `widgets.app.com`. With path-prefix routing, the cookie is shared
  unless you use cookie-path, which breaks login UX.
- **CSP, CORS, and origin headers all enforce isolation for free.** A tenant-A page can't
  fetch `tenant-B/api/...` without explicit CORS allow.
- **Templates can ignore tenancy in URLs.** `<a href="/people/123">` works the same on
  every tenant; URL prefixes would require base-path-aware routing helpers everywhere.
- **Tenant resolution is one-line: parse the host header.** No path parsing, no query
  param trust, no header-spoofing concerns from internal proxies.

**What this rules out.** Co-tenanted browser sessions. If a user belongs to two tenants,
they must log in twice — once per subdomain. This is consistent with D1 (tenant-local
identity).

**Custom domains.** Day-1 supported via a `tenant_domains` table mapping
`example-customer.com` → `tenant_id`. The resolver tries the host header against
that table first, falls back to subdomain extraction. ACME is handled by the ingress
(Caddy with on-demand TLS, or cert-manager with `Issuer` per Ingress).

### D3. Database strategy: shared DB + `tenant_id` + PostgreSQL Row-Level Security

One Postgres database, every tenant table has `tenant_id UUID NOT NULL REFERENCES tenants(id)`,
and Row-Level Security (RLS) policies enforce isolation at the database layer.

**Rationale.** Three options, ranked by isolation strength:

1. Database-per-tenant (or schema-per-tenant)
2. Shared DB + `tenant_id` + RLS *(this choice)*
3. Shared DB + `tenant_id` + app-side filtering only

Option 1 has bulletproof isolation but at operational cost: per-tenant migrations,
backup/restore complexity, connection-pool scaling problems past a few hundred tenants.
Option 3 fails to a single missed `.where(tenant_id == ...)`. Option 2 makes the database
the failsafe: even if the application forgets to filter, RLS will return zero rows.

**Database roles.** Three Postgres roles:

- `app_user` — owns the connection from the FastAPI/Celery app. Has RLS enforced.
  Cannot bypass. Sets `app.current_tenant` per request via `SET LOCAL`.
- `platform_api` — used by online platform routes such as tenant provisioning and
  support exports. Does not have `BYPASSRLS`; it has explicit grants on platform tables
  and must set tenant context before writing tenant-scoped rows.
- `app_admin` — used only by Alembic migrations and offline maintenance scripts.
  Bypasses RLS. Should never be used by request-handling code.

**Why roles, not `SECURITY DEFINER` functions.** Defining bypass functions per
operation is more code, more attack surface, and harder to audit. Two roles is one
boundary, easy to reason about. Request-path connection pools use `app_user` and
`platform_api`; `app_admin` is reserved for offline operations.

### D4. Repo strategy: new repo (`dotmac_starter_mt`)

This codebase, not a branch on `dotmac_starter`. The single-tenant starter remains as-is
for products that don't need tenancy.

**Rationale.** Multi-tenancy is structural. Every model has `tenant_id`, every service
filters by it, every test creates two tenants and asserts isolation. Branching means every
existing commit becomes pre-tenant baggage; the diff is so large that it's a rewrite anyway.
A clean-slate repo lets the initial migration be tenant-aware from line one.

We will copy patterns liberally from `dotmac_starter` (CSRF middleware, rate limiter, audit
log structure, error handlers, observability) — but not migrations, models, or service code.

## Detailed Designs

### Tenant Resolver

Middleware order in `app/main.py`:

1. `TrustedHostMiddleware` / ingress host validation — rejects unknown hosts and only
   trusts forwarded host headers from configured proxies.
2. `TenantResolverMiddleware` — extracts the validated host and looks up the tenant.
3. `RateLimitMiddleware` — keyed by `(tenant_id, client_ip, path)`.
4. `CSRFMiddleware`.
5. `AuthMiddleware` — validates session/JWT and asserts `session.tenant_id == request.state.tenant.id`.

Resolution algorithm:

```
host = request.headers["host"].split(":")[0]
1. SELECT tenant_id FROM tenant_domains WHERE domain = host AND verified_at IS NOT NULL
   → if found: request.state.tenant = Tenant(...); return
2. If host ends with platform_root_domain (e.g., ".app.com" or ".localhost"):
   slug = host[:-len(platform_root_domain)]
   SELECT id FROM tenants WHERE slug = :slug AND is_active = true
   → if found: request.state.tenant = Tenant(...); return
3. If host == platform_root_domain:
   request.state.tenant = None  # platform-level (signup, marketing, admin console)
   return
4. Otherwise: 404 "Tenant not found"
```

Failure mode: every protected route uses a `Depends(require_tenant)` that raises `404`
if `request.state.tenant is None`. Platform admin routes use `Depends(require_platform_admin)`
which both requires `tenant is None` AND validates a separate `platform_admin` role.

### DB Connection: Setting Tenant Context

The `get_db` dependency:

```python
def get_db(request: Request) -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        if request.state.tenant is not None:
            db.execute(text("SET LOCAL app.current_tenant = :id"),
                       {"id": str(request.state.tenant.id)})
        # else: platform path or unresolved request — tenant context NOT set
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
```

`SET LOCAL` is transaction-scoped; the next request gets a connection from the pool with
no tenant context set, then the new request's `get_db` sets its own. RLS policies read
`app_current_tenant_id()`, which wraps `current_setting('app.current_tenant', true)`,
treats empty or malformed values as `NULL`, and lets RLS fail closed when context isn't set.

Background tasks have a parallel pattern in `app/celery_app.py`:

```python
@task_prerun.connect
def set_tenant_context(task_id, task, args, kwargs, **_):
    tenant_id = task.request.headers.get("tenant_id") if task.request.headers else None
    if tenant_id:
        # Open a session, SET LOCAL app.current_tenant = tenant_id, store on context
        ...
```

Every task that touches tenant data MUST be enqueued with a `tenant_id` header. Workers
fail-closed if the header is missing and the task touches a tenant table.

### RLS Policy Template

For every tenant table (e.g., `people`):

```sql
ALTER TABLE people ENABLE ROW LEVEL SECURITY;
ALTER TABLE people FORCE ROW LEVEL SECURITY;  -- forces RLS for table owner too

CREATE OR REPLACE FUNCTION app_current_tenant_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant', true), '')::uuid;
EXCEPTION
    WHEN invalid_text_representation THEN
        RETURN NULL;
END;
$$;

CREATE POLICY people_tenant_isolation ON people
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());
```

`USING` controls visibility on read; `WITH CHECK` controls writes (INSERT/UPDATE).
The `FORCE` clause is critical because every request-path role must hit RLS. Only
`BYPASSRLS` roles such as `app_admin` skip it, and those roles are not used by request
handlers.

The migration template adds RLS in the same transaction as the table create. There's no
"add tenant_id later" path; if a model exists, it has `tenant_id` from day one.

### Auth Flow

JWT claims include both `sub` (person UUID) and `tenant_id` (UUID).

`require_user_auth` dependency:

1. Decode JWT.
2. Assert `payload["tenant_id"] == request.state.tenant.id`. Mismatch → 401.
3. Look up `AuthSession` by token hash. Assert `session.tenant_id == request.state.tenant.id`.
4. Look up `Person` by `payload["sub"]`. RLS automatically scopes the query to the current
   tenant; if the person doesn't belong, the lookup returns nothing → 401.
5. Attach `current_person` to request state.

Login flow:

1. POST to `/auth/login` on `acme.app.com` with email + password.
2. Resolver sets `request.state.tenant = acme`.
3. `get_db` sets `app.current_tenant = acme.id`. RLS scopes the query.
4. `select(UserCredential).where(email == ...)` — RLS filters to acme's people.
5. Issue JWT with `tenant_id = acme.id` claim. Set cookie scoped to `acme.app.com`.

Cross-tenant attack: a user with a valid JWT for `acme.app.com` who tries to access
`widgets.app.com` with that JWT will fail at step 2 of `require_user_auth` (claim mismatch).
Even if they bypass that, the `AuthSession.tenant_id` check at step 3 catches it. Even if
they bypass that, RLS at the DB layer ensures they see no `widgets` data. Three layers.

### Tenant Lifecycle

Provisioning:

1. Platform admin POSTs to `/platform/tenants` with `slug`, `name`, owner email + password.
2. Inside one transaction (via `platform_api`, no RLS bypass):
   - Insert `tenants` row.
   - Set `app.current_tenant` to the new tenant id.
   - Insert seed `roles` (admin, member) for that tenant.
   - Insert owner `people` + `user_credentials` + `person_roles(admin)`.
3. Return tenant + initial login credentials.

Suspension:

- Set `tenants.is_active = false`. Resolver returns 404 for the slug, blocking all access.
- Existing JWTs for the tenant become unusable — the `require_user_auth` dependency
  re-validates the tenant on every request.

Hard delete (GDPR):

- Two-phase: soft-mark `deleted_at = now()`, schedule an offline maintenance job after a
  configurable retention window (default 30 days) to do the actual `DELETE` on every
  tenant table via `app_admin`.
- Hard delete is one query per table with `WHERE tenant_id = :id`. FK ordering matters —
  documented in the deletion script.

Data export:

- Platform admin endpoint that streams a zip of CSVs per tenant table. Read-only via
  `platform_api`; it sets `app.current_tenant` to the exported tenant and still uses
  explicit `WHERE tenant_id = :id` as a safety belt.

### Audit Log Immutability

Audit events table is append-only by privilege:

```sql
CREATE ROLE app_user_audit_writer NOINHERIT;
GRANT INSERT ON audit_events TO app_user_audit_writer;
-- No UPDATE, no DELETE for app_user (or any role used by app code).
-- app_admin has full access for retention deletion only.
```

Audit middleware uses a separate `audit_db` dependency that connects as the writer role.
Application code cannot mutate audit history even with a SQL injection bug.

### Per-Tenant Rate Limiting

Redis key:

```
rate_limit:{tenant_id}:{client_ip}:{path}
```

Tenant prefix prevents one tenant from exhausting the rate limit budget for another.
Tenant-specific limit overrides live in `tenant_settings.rate_limit_*` and fall back to
platform defaults.

### Background Jobs

Every `enqueue_task()` call requires a `tenant_id` (or explicit `is_platform_task=True`).
Helpers in `app/services/queue.py`:

```python
def enqueue_for_tenant(task, tenant_id: UUID, *args, **kwargs):
    return task.apply_async(args=args, kwargs=kwargs, headers={"tenant_id": str(tenant_id)})

def enqueue_platform(task, *args, **kwargs):
    return task.apply_async(args=args, kwargs=kwargs, headers={"is_platform_task": "true"})
```

Workers refuse to run a task that touches tenant data without a `tenant_id` header
(checked in a Celery `task_prerun` signal handler).

### WebSockets

Connection manager keys: `(tenant_id, person_id)`. Redis pub/sub channels:
`ws:tenant:{tenant_id}:notifications`. A notification published to tenant A's channel is
never delivered to tenant B's subscribers because they're on a different channel.

WebSocket auth handshake must run equivalent host-based tenant resolution before
validating the JWT's `tenant_id` claim. HTTP middleware does not automatically cover
WebSocket scopes, so this is a separate ASGI/resolver path.

### File Storage

Object key structure: `tenants/{tenant_id}/{category}/{filename}`. The `tenant_id` prefix
is enforced in `FileUploadService.upload()` — the service receives `tenant_id` from
`request.state.tenant` (NOT from a request param) and prepends it. Path traversal guards
ensure no `..` escapes from `category` or `filename`.

S3 bucket policies should additionally enforce `s3:prefix = "tenants/${aws:userid}/"` if
using per-tenant IAM roles (out of scope for v1, documented as upgrade path).

### Settings: Platform vs Tenant

- **Platform settings** (global): JWT signing keys, S3 backend config, trusted proxies,
  rate limit defaults. Stored in `platform_settings` table or env. Operator-controlled.
- **Tenant settings**: branding, auth policy (MFA required?), billing config, scheduler
  config. Stored in `tenant_settings(tenant_id, key, value)`. Tenant-admin-controlled.

There is no `domain_settings` table in v1. The split is hard, not soft.

### Test Invariants

Every cross-cutting feature MUST have an explicit cross-tenant test that:

1. Creates two tenants A and B.
2. Creates an entity in A.
3. Switches the request context to B (different host header).
4. Asserts list/get/update/delete of the entity from B's context returns 404 — even when
   the exact UUID is provided.
5. Asserts the same operation from A's context succeeds.

These tests are the canary for any new tenant-scoped table. CI fails if a table has no
cross-tenant test.

## Failure Modes

| Failure | Detection | Mitigation |
|---|---|---|
| Service forgets `where(tenant_id == ...)` | RLS returns 0 rows; cross-tenant test fails. | RLS is the safety belt. Cross-tenant tests are the alarm. |
| Background task missing `tenant_id` header | `task_prerun` raises; worker logs error. | Worker fail-closed. |
| `app_admin` role accidentally used by app code | Startup/test fixture asserts request engines use `app_user` or `platform_api`, never `app_admin`. | DB role separation. |
| `SET LOCAL app.current_tenant` missing | RLS returns 0 rows (NULL setting). | Fail-closed by RLS design. |
| JWT issued for tenant A, used on tenant B subdomain | `require_user_auth` claim check fails → 401. | Auth dep validation. |
| Cookie scope leak | Subdomain cookie scope (browser-enforced). | D2 routing decision. |
| Custom domain hijack | Domain verification (DNS TXT) before activation. | `tenant_domains.verified_at` gate. |
| Tenant deletion leaves orphans | Single transaction across all FK-ordered tables. | Hard-delete script with explicit table order. |

## What's NOT in v1

Documented to set expectations:

- Cross-tenant identity / SSO across tenants
- Per-tenant database (option 1 from D3)
- Tenant migration from one DB to another (sharding)
- Tenant data import (only export)
- Multi-region tenant data residency
- Tenant-level audit log encryption keys (use platform-wide)
- Real-time tenant usage metering (basic counters only)
- Hierarchical tenants (parent/child orgs) — flat tenant graph only

## Test Plan

Repo-level smoke tests:

- `test_cross_tenant_isolation.py` — two tenants, can't read each other's people
- `test_rls_enforced.py` — direct DB session as `app_user` returns no rows when
  `app.current_tenant` is unset
- `test_tenant_resolver.py` — host header parsing covers subdomain, custom domain, missing,
  invalid
- `test_auth_tenant_claim.py` — JWT for tenant A rejected on tenant B
- `test_audit_immutability.py` — `app_user` role cannot UPDATE or DELETE `audit_events`

Skeleton ships with the cross-tenant isolation test first. The remaining tests are required
before v0.1 is considered complete.

## Open Questions for v0.2+

- Per-tenant encryption-at-rest keys (KMS integration)
- Per-tenant Celery queue priorities
- Tenant data residency / EU-only tenants on EU infra
- Tenant-level retention policies on audit log
- Webhook signing per tenant (separate signing key per tenant)

These are tracked but deferred until a real product surfaces the requirement.

## References

- PostgreSQL RLS: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- `dotmac_starter` (single-tenant predecessor): patterns copied where applicable
