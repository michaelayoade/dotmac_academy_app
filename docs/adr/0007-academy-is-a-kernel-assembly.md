# ADR 0007 — Academy Is a Kernel Product Assembly

**Status:** Accepted  
**Date:** 2026-08-11  
**Implements:** platform ADR-0015, `dotmac_academy_app` is an assembly or a fork

## Context

Academy imported kernel configuration, database, tenancy, and exception
utilities while constructing its own FastAPI application and carrying copies of
all five kernel middleware modules. That split authority caused a real failure:
`TENANCY=single` was configured, but the kernel lifespan that binds the sole
tenant never ran.

The Academy domain is not the application runtime. Learning, admissions,
assessment, labs, reporting, and their state transitions belong to Academy.
Application construction, generic request controls, tenancy resolution, and
startup enforcement belong to the platform kernel.

## Decision

Academy is a product assembly over the pinned `dotmac-kernel` release.

- `app.assembly` is the single declaration of Academy's API and web routers,
  template/static layers, topology, and migration directory.
- `dotmac_kernel.create_app` owns FastAPI construction, the lifespan, generic
  liveness, tenancy binding, static/template composition, error translation,
  and CSRF, rate-limit, tenant, observability, and security-header middleware.
- Academy retains its routes, services, product models, and Alembic lineage.
  They are mounted through one transitional `FeatureManifest`. It does not
  claim an independent module namespace or migration lineage that does not yet
  exist.
- Academy domain exceptions are compatibility imports of the kernel exception
  classes, so the kernel is the one HTTP error translator.
- Product validation and GlitchTip initialization are declared as ordered
  startup checks/hooks on the assembly. Academy request metrics and GlitchTip
  request-id correlation remain one narrow product instrumentation adapter;
  they do not reimplement a generic middleware decision.

Academy remains a single-Academy deployment. Kernel a38's
`platform_surface_enabled=False` omits platform authentication and web routers
during composition, so the accepted offline-only tenant/bootstrap authority in
ADR-0002 is not silently reopened. Academy does not delete already-mounted
FastAPI routes or inspect FastAPI's lazy included-router internals.

Academy's current pages also require inline scripts and same-origin WebSockets.
The assembly supplies that product CSP plus COOP/CORP through
`ProductSecurityPolicy` to the kernel-owned header middleware. This is a policy
value, not a second header writer. Moving inline scripts to versioned assets
can tighten the value later without changing runtime ownership.

## Ownership and cutover

| Concern | Old owner | New owner | Verification |
|---|---|---|---|
| FastAPI construction and lifespan | `app.main` | `dotmac_kernel.create_app` | Architecture test forbids construction in `main.py` |
| Single-tenant startup binding | Academy copy of kernel logic | Kernel lifespan | Real Academy app lifespan test proves binding and multi-row refusal |
| Five generic middleware components | `app.middleware.*` copies | `dotmac_kernel.middleware.*` | Duplication baseline shrinks by five; app stack test checks module owners |
| Route inventory | Imperative registrations in `app.main` | `app.assembly.academy_feature` | Manifest is the one router declaration |
| Domain error translation | Academy handlers | Kernel handlers | Academy exceptions alias kernel exception classes |
| Tenant/bootstrap administration | Offline Academy CLI | Offline Academy CLI | `/platform` routes are absent from the composed app |
| Product startup and browser policy | Academy pre-factory mutation/middleware adapters | Kernel a38 assembly checks, hooks, and `ProductSecurityPolicy` | Architecture tests pin the fields and forbid the retired adapters |

The rollback point is the last release before this cutover. There is no shadow
runtime: running two middleware/lifespan decision paths would recreate the
split authority this ADR removes. CI behavior and architecture tests are the
cutover gate.

The error-owner cutover also adopts the kernel JSON envelope
(`code`, `message`, `details`, and `request_id`) in place of Academy's former
single `detail` field. This is one intentional API contract change, not a
parallel compatibility response maintained by Academy.

## Deferred work

This change intentionally does not migrate `Base`, `Tenant`, `Role`,
`UserCredential`, `AuthSession`, `PersonRole`, or the Academy migration lineage.
Those changes affect database identity and require their own ownership ledger,
schema verification, cutover, and rollback plan. The duplication ratchet keeps
the remaining seven model collisions visible and prevents new ones.

Kernel 0.1.0a38 completed the former platform-surface, startup-hook, and product
security-policy follow-ups. The a32 compatibility adapters are retired in this
cutover; no parallel route filter, settings mutation, or browser-header writer
remains in Academy.
