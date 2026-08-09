# Aligning `dotmac_academy_app` with the platform kernel — gap analysis

**Status:** analysis, not a decision. No work is authorised by this document.
**Date:** 2026-08-09. **Kernel surveyed:** `dotmac-kernel` 0.1.0a28.

> **Corrected 2026-08-09.** The first version of this document claimed the
> `Person` → `Party` migration was a prerequisite for kernel-owned roles, and
> put it at "months, not weeks". That was written from class names before the
> columns were compared, and it is wrong in the way that matters: it makes the
> whole thing look unaffordable. Comparing the actual models shows `Role` is
> already column-identical, `Tenant` differs by two columns, and `PersonRole`
> differs from `PartyRole` by one. The full `Person` → `Party` migration is
> still months — it is just **not on the path** to kernel-owned tenancy and
> roles. Sections below are corrected; the sequencing changed as a result.

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
`dotmac_starter_mt` #79 (`tenant_session` + `set_tenant`, kernel 0.1.0a28).

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
| **`Person`** (`models/person.py`) | **`Party`, `PartyPerson`, `PartyOrganization`** | The one semantic divergence. The kernel generalised person → party so an *organization* can hold a role. We did not. Note what this does and does not block — see "What the columns actually say". |
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

## What the columns actually say

Class names are not models. Compared field by field against kernel 0.1.0a28:

**`Role` — already identical. A drop-in.**

    academy:  id, tenant_id, slug, name   (+ TimestampMixin, table "roles")
    kernel:   id, tenant_id, slug, name   (+ TimestampMixin, table "roles")

Delete ours, import the kernel's. The only possible delta is the kernel's two
unique constraints (`uq_roles_tenant_slug`, `uq_roles_tenant_id_id`) — confirm
they exist here and add them if not.

**`Tenant` — identical apart from two columns we bolted on.** Both models carry
`id, slug, name, is_active, suspended_at, deleted_at` and a `domains`
relationship. We added `default_entrance_bank_id` and
`default_entrance_time_limit_minutes`.

That is the whole tenancy gap, and it is a boundary violation rather than a
schema problem: a product concern was put on a platform model. The fix is to
move both to a product-owned table keyed by `tenant_id` (`academy_tenant_config`
or similar), after which `Tenant` and `TenantDomain` are adoptable unchanged.

Not the kernel settings facility, despite the temptation:
`default_entrance_bank_id` is a foreign key into our `question_banks`, and a
platform settings store holding an FK to a product table recreates the same
violation one layer down.

**`PersonRole` → `PartyRole` — one column.**

    academy PersonRole:  id, tenant_id, person_id, role_id   table "person_roles"
    kernel  PartyRole:   id, tenant_id, party_id,  role_id   table "party_roles"

So the migration is: create a `Party` (+`PartyPerson`) per existing `Person`,
reusing `person.id` as `party.id` so the rewrite is an identity map; rename
`person_roles` → `party_roles` and `person_id` → `party_id`.

**Everything else in this repo keeps using `Person`.** `Party` enters as the
identity-for-*authorisation* only; `Person` stays the academy learner record.
Enrolments, certificates, submissions and audit rows do not move.

`db`, `config`, `security` and `audit` are mechanical — kernel imports with
contained blast radius.

**The extraction gate applies** (`docs/inventories/module-extraction-sources.md`
in `dotmac_starter_mt`): named contract first, port the production-proven
implementation with its tests, cut the source product over, then a second
consumer on a released pin. Academy would be a *consumer*, so the relevant bar
is adoption, not extraction — but the gate is why this cannot be done by
opportunistic copying.

## Suggested sequencing

Each step is independently valuable and independently abandonable. Nothing below
is started.

1. **Adopt kernel 0.1.0a28 for `db` only.** Delete `app/db.py`, import
   `get_db`/`tenant_session`/`set_tenant` from the kernel. Smallest possible
   proof that this repo can pin and consume the kernel at all, and it retires
   the exact fork that caused the incident. *This is the one I would do next.*
2. **`config`, `security`, `audit`.** Contained, no schema change. Audit gains
   the kernel's declared-action registry, which is a real improvement over
   free-form event names.
3. **`Role` → kernel.** Column-identical; a delete-and-import.
4. **Move the two product columns off `Tenant`**, then adopt kernel `Tenant`
   and `TenantDomain`. One small migration, no identity change.
5. **`Party`/`PartyPerson` alongside `Person`; `person_roles` → `party_roles`.**
   The only identity migration on this path, and it is narrow — role assignment
   only. After this, tenancy, roles and authorisation are kernel-owned.
6. **Write the ADR** proposing academy as a fourth assembly, or explicitly
   rejecting it. Steps 1–5 are worth doing either way.
7. **Full `Person` → `Party`** — every enrolment, certificate, submission and
   audit row. Months, shadow phase, cutover gate, fallback retirement. **This is
   optional and blocks nothing above it.** Worth doing only if academy needs an
   *organization* to hold a role, which today it does not.

## Open questions for Michael

- Is academy intended to be a fourth ADR-0003 assembly, or a product that merely
  *borrows* kernel packages? The answer changes whether step 7 is ever worth it.
- Does anything here need an **organization** to hold a role — a partner company
  or corporate customer, rather than a named person? That, and only that, is
  what makes the full `Person` → `Party` migration worth its cost.
- Do `dotmac_erp`, `dotmac_sub` and the vendor control plane have the same bare
  `SessionLocal` exposure in their CLI/batch code? I confirmed academy and fixed
  the kernel; I have not audited the others, and the failure is silent in all of
  them.
