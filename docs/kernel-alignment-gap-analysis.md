# Aligning `dotmac_academy_app` with the platform kernel — gap analysis

**Status:** analysis, not a decision. No work is authorised by this document.
**Date:** 2026-08-09. **Kernel surveyed:** `dotmac-kernel` 0.1.0a26 (`dotmac_starter_mt` @ `d20f932`).

## Why this exists

On 2026-08-09 a production incident on `academy.dotmac.io` traced to this repo's
`app/db.py`, which is a **fork of `dotmac_kernel/db.py`**. The kernel copy had
since grown `platform_session` — an owned boundary for code running outside the
request cycle. Ours had not. Every CLI command opened a bare `SessionLocal` with
no RLS tenant scope, and because RLS fails *closed*:

- `audit-banks --tenant-slug dotmac` printed `TOTAL 0 0` against a database
  holding **333 question banks and 3,210 questions for that tenant** — a
  compliance tool certifying an estate it could not see;
- `load-banks` skipped every file with *"course not found"* and had silently
  deployed nothing for **37 commits** of content fixes.

Neither command ever failed. The fix landed here as #111 and upstream as
`dotmac_starter_mt` #79 (`tenant_session` + `set_tenant`, kernel 0.1.0a27).

That is the concrete argument for alignment: we hand-rolled a kernel-owned
facility, drifted from it, and the drift was invisible until it took production
down. This document sizes what else is in that category.

## What the kernel owns

Per its own distribution metadata: *"multi-tenant FastAPI foundation (config,
RLS db, identity/tenancy models, security, platform auth, middleware, settings,
features registry, audit)"*. ADR-0003 (`dotmac_starter_mt`) makes maintained
products **thin assemblies pinning versioned kernel releases**.

Academy is **not** one of ADR-0003's three assemblies (vendor control plane,
`dotmac_sub`, `dotmac_erp`). Aligning means proposing a fourth, which is a
programme, not a refactor.

## The overlap

### Models — same lineage, same names

| This repo | Kernel | Assessment |
|---|---|---|
| `Tenant`, `TenantDomain` (`models/tenant.py`) | `Tenant`, `TenantDomain` | Same names. Almost certainly a common ancestor. |
| `UserCredential`, `AuthSession` (`models/auth.py`) | `UserCredential`, `AuthSession` | Same names. |
| `Base`, `TimestampMixin` (`models/base.py`) | `Base`, `TimestampMixin` | Same names. |
| `Role`, `PersonRole` (`models/rbac.py`) | `Role`, `PartyRole` | Renamed with the Party generalisation. |
| **`Person`** (`models/person.py`) | **`Party`, `PartyPerson`, `PartyOrganization`** | **The one real semantic divergence.** The kernel generalised person → party so an org can hold a role. We did not. |
| `AuditEvent` (`models/rbac.py`) | `dotmac_kernel.audit` | Kernel has a declared action registry; ours is free-form. |
| `PlatformSetting` (`models/platform_settings.py`) | `dotmac_kernel.settings*`, `models_platform` | Kernel has scopes, typed values, encryption, caching, a resolver. |

### Services — parallel implementations

`app/db.py`, `app/config.py`, `app/services/audit.py`, `app/services/identity.py`,
`app/services/security.py`, `app/services/entitlements.py` all have kernel
counterparts.

### Kernel facilities we have no equivalent of

`branding`, `capabilities`, `features`/`flags`, `permissions`, `licensing`,
`modules` (ModuleManifest/Registry), `money`, `crud`, `query`, `templating`,
`settings_resolver`, `messaging`/outbox, `namespaces`, `profiles`,
`secret_sources`, `display`.

## Honest assessment of the difficulty

**The `Person` → `Party` migration is the hard part and it is not optional.**
Every role assignment, enrolment, certificate, submission and audit row in this
repo hangs off `Person`. The kernel's `PartyRole` binds to `Party`. There is no
adapter that makes those the same object; it is a data migration across the
whole schema with a live tenant on it.

Everything else is comparatively mechanical. `db`, `config`, `security` and
`audit` could be swapped for kernel imports with contained blast radius.

**The extraction gate applies** (`docs/inventories/module-extraction-sources.md`
in `dotmac_starter_mt`): named contract first, port the production-proven
implementation with its tests, cut the source product over, then a second
consumer on a released pin. Academy would be a *consumer*, so the relevant bar
is adoption, not extraction — but the gate is why this cannot be done by
opportunistic copying.

## Suggested sequencing

Each step is independently valuable and independently abandonable. Nothing below
is started.

1. **Adopt kernel 0.1.0a27 for `db` only.** Delete `app/db.py`, import
   `get_db`/`tenant_session`/`set_tenant` from the kernel. Smallest possible
   proof that this repo can pin and consume the kernel at all, and it retires
   the exact fork that caused the incident. *This is the one I would do next.*
2. **`config`, `security`, `audit`.** Contained, no schema change. Audit gains
   the kernel's declared-action registry, which is a real improvement over
   free-form event names.
3. **Write the ADR** proposing academy as a fourth assembly — or explicitly
   rejecting it. Steps 1–2 are worth doing either way; step 4 is not worth
   starting without a decision.
4. **`Person` → `Party`.** Schema migration, shadow phase, cutover gate,
   fallback retirement, boundary tests. Months, not weeks.

## Open questions for Michael

- Is academy intended to be a fourth ADR-0003 assembly, or a product that merely
  *borrows* kernel packages? The answer changes whether step 4 is ever worth it.
- Do `dotmac_erp`, `dotmac_sub` and the vendor control plane have the same bare
  `SessionLocal` exposure in their CLI/batch code? I confirmed academy and fixed
  the kernel; I have not audited the others, and the failure is silent in all of
  them.
