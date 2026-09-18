# ADR 0008 — Kernel Identity and Migration-Lineage Cutover

**Status:** Accepted; schema implementation is gated by the rehearsals below  
**Date:** 2026-08-11  
**Extends:** ADR 0007, Academy Is a Kernel Product Assembly  
**Inventory:** `docs/inventories/kernel_identity_lineage_cutover.toml`

## Context

ADR 0007 moved Academy's application runtime to `dotmac-kernel`, but deliberately
left database identity and migration ownership with Academy. The remaining
boundary is not seven independent import substitutions:

- Academy still defines the seven kernel-name collisions in the inventory:
  `Base`, `TimestampMixin`, `Tenant`, `TenantDomain`, `Role`, `UserCredential`,
  and `AuthSession`.
- `Person`/`PersonRole` are semantic predecessors of kernel
  `Party`/`PartyRole`, and `audit_events.actor_person_id` is another dependent
  identity edge.
- Twenty-seven Academy columns carry human identity. Twenty-four say `person`
  in the column name; `attempt_grants.granted_by` and
  `success_queue_entries.assigned_to`/`resolved_by` are the three semantic
  aliases. Eleven currently have physical foreign keys to `people`; sixteen are
  logical references only.
- Academy and kernel both ship revision `0001_initial_tenant_schema`. Their DDL
  functions are AST-equivalent, but two files declaring the same revision make
  a composed Alembic graph fail before it can run.
- Kernel revision `0003_party_identity` is explicitly destructive: it was
  written for an empty starter and drops `people`, `person_roles`,
  `user_credentials`, and `auth_sessions`. It must never execute against an
  Academy database containing production identity.

The current Academy lineage also mixes platform tables and Academy product
tables in one numeric chain. Keeping that chain as the permanent assembly
lineage would preserve the original ownership ambiguity and would make
branch-aware rollback unreliable because its root is also the kernel root.

## Decision

Academy will adopt kernel identity through a non-destructive expand/shadow/
cutover/contract programme, then rebaseline its product schema as an independent
`assembly` lineage. Directly composing today's two version directories is
forbidden.

### Composable baseline and fleet sequence

This cutover does **not** move Academy identity into Starter. Starter remains a
reference assembly and migration-pattern exemplar; `dotmac-kernel` is the
platform owner, and Academy remains the owner of its product extensions and
legacy-source mapping.

The implementation deliberately composes the strongest proven boundary from
each existing system instead of copying any one product schema:

| Concern | Pattern to reuse | Boundary not copied |
|---|---|---|
| Canonical security identity | Kernel's tenant-scoped `Party`, subtypes, credentials, sessions, RBAC, composite tenant constraints, RLS, and single email authority | No Academy, Sub, or ERP identity model is promoted into Starter or kernel |
| Schema and lineage adoption | Starter's `a001_adopt_custom_field_definitions` create-or-adopt revision and PostgreSQL migration rehearsals: full catalog/RLS/grant verification, drift rejection, destructive-downgrade refusal, and real stamp/rollback proof | Starter is not a runtime identity system of record |
| Legacy-data adoption | Sub's party-identity audit, adjudication, exact-plan digest, expiring approval, serializable execution, row locking, idempotent receipt, and drift/collision/repoint refusal | Sub's untenant-scoped business-party tables and business-role vocabulary are not kernel RBAC and are not copied |
| External authentication | ERP's replaceable OIDC-provider boundary: bind exact issuer/subject locally, create a local session, and ignore provider authorization claims | ERP's legacy `Person`, credential, session, and RBAC schema is not copied |

The checked-in reference evidence is:

- `dotmac_starter_mt/docs/adr/0017-adoption-is-the-scarce-resource.md`;
- `dotmac_starter_mt/alembic/versions/a001_adopt_custom_field_definitions.py` and
  `dotmac_starter_mt/tests/test_migration_split_rehearsals.py`;
- `dotmac_sub/docs/PARTY_ROLE_RELATIONSHIP_SOT.md`,
  `app/services/party_identity_audit.py`,
  `app/services/party_identity_adjudication.py`,
  `app/services/party_identity_backfill.py`, and
  `tests/test_party_identity_backfill.py`; and
- `dotmac_erp/docs/oidc_identity_contract.md`.

Accepted Starter ADR 0017 makes adoption the scarce resource and names Sub as
the reference kernel-lineage adopter. Academy may design its adapter and its
rehearsals now, but it must not activate the identity lineage transfer until
Sub has run the released kernel lineage in a product database and the reusable
findings have been incorporated here. Academy also does not add a speculative
kernel identity-adoption SDK: it uses existing released kernel surfaces. A new
public kernel seam is extracted only after Sub and Academy demonstrate the same
need, making that extraction demand-pulled.

If the Sub gate advances the required kernel revision beyond Academy's pinned
version, Academy updates and validates that dependency in a separate adoption
change before changing this ADR's lineage endpoints. It does not silently
substitute a newer head during a database cutover.

### Target ownership

| State | Owner before cutover | Owner after cutover |
|---|---|---|
| Declarative base and timestamp contract | Academy | kernel `Base`, `TimestampMixin`, `uuid_pk` |
| `tenants`, `tenant_domains`, `roles` | Academy legacy lineage | kernel models and kernel lineage; rows and UUIDs stay in place |
| Human identity, email, active state, names | Academy `people` | kernel `Party` + `PartyPerson` |
| Academy avatar/preferences | Academy `people` | Academy `academy_person_profiles`, keyed to the kernel party |
| Password credential and session | Academy models | kernel `UserCredential` and `AuthSession` |
| Login failure count and lockout deadline | columns on the credential | Academy `academy_login_security`; `web_auth.authenticate` remains the sole policy writer |
| Role definitions and grants | Academy `Role`/`PersonRole` | kernel `Role`/`PartyRole` |
| Tenant audit ledger and actor identity | Academy model/service | kernel `AuditEvent`/declared action registry, using `actor_party_id` |
| Academy learning/admissions/lab/reporting tables | Academy legacy lineage | independent host `assembly` lineage |

This keeps login lockout as one Academy product decision without extending the
kernel credential schema privately. SMTP, routes, and UI remain adapters; they
do not become identity writers.

### Identity mapping

The migration is an identity map, not a remint:

- `parties.id = people.id` and `party_persons.party_id = people.id`.
- `party_type = 'person'`.
- `Party.email` receives the normalized Academy email and becomes the sole email
  authority. A case-insensitive collision is a hard pre-cutover failure.
- `Party.display_name` uses the kernel `person_display_name(first_name,
  last_name)` rule; `PartyPerson` owns the component names.
- `Party.is_active = (people.status = 'active')`. Academy currently permits only
  `active` and `suspended`; any other value blocks cutover.
- `academy_person_profiles` receives `avatar_path` and `prefs`. Those values do
  not move into kernel `custom_fields` because they are Academy presentation
  state, not fleet-wide identity.
- `party_roles` preserves `person_roles.id`, `tenant_id`, and `role_id`, with
  `party_id = person_id`.
- Existing product columns named `person_id`, `author_person_id`, or
  `instructor_person_id` keep those names: they mean a human participant in the
  Academy domain, not an arbitrary party. Their UUID values remain unchanged.
  Existing strong references are retargeted to `parties` and the person subtype;
  currently FK-less references remain explicitly classified and are checked for
  orphans before the legacy `people` table can retire.
- The three actor/assignee aliases (`granted_by`, `assigned_to`, `resolved_by`)
  also retain their UUIDs and human semantics. They are explicitly inventoried
  so a name-based scan cannot hide them from the shadow and orphan checks.

`user_credentials` and `auth_sessions` retain their table and row IDs. The
expand phase adds/backfills `party_id` and enforces `party_id = person_id` while
legacy code is a supported fallback. Credential email is a read-only
compatibility projection from `Party.email`, never a second authority. Login
failure state is copied to `academy_login_security` before kernel models become
the runtime writer.

### One writer in every phase

The shadow period is directional:

1. Before runtime cutover, `people` is authoritative and one projector writes
   `Party`, `PartyPerson`, the Academy profile, and compatibility identity
   columns. Kernel-shaped reads are compared but do not write identity.
2. At cutover, a maintenance gate runs the reconciler, proves zero drift, and
   flips the direction. `Party`/`PartyPerson` become authoritative; one
   compatibility projector keeps the legacy tables readable for the named
   fallback release.
3. The two runtimes are never active writers concurrently. A rollback first
   runs the reverse reconciliation and flips authority under the same
   maintenance gate.
4. After the observation window, the fallback projection and legacy tables are
   retired. No parallel decision path remains.

### Migration-lineage transfer

The final graph has two independently owned roots:

```text
kernel:   0001_initial_tenant_schema -> ... -> 0020_delivery_receipts

assembly: a001_adopt_academy -> a002 -> ...
          down_revision = None
          branch_labels = ("assembly",)
          depends_on = "0020_delivery_receipts"
```

The existing numeric Academy chain (`0001` ... `0053`, followed by the bridge
revisions) is a temporary `academy_legacy` lineage. It is not relabelled or
reparented: those IDs may already be recorded. The installed kernel copy becomes
the only selected file for the shared `0001` during the transitional tooling;
the equivalent Academy root is not selected, preventing a duplicate revision.

The cutover sequence is:

1. **Legacy expand.** A revision after the current Academy head creates and
   backfills the kernel-shaped identity tables/columns plus Academy profile and
   lockout state. It drops nothing required by the fallback release.
2. **Kernel bridge.** Apply kernel `0002_settings_table` normally. After the
   full target-catalog verifier passes, stamp `0003_party_identity` instead of
   executing it. Apply `0004_custom_fields` normally. A bare or unverified stamp
   is forbidden.
3. **Runtime cutover.** Deploy kernel-model readers/writers, flip the one-way
   identity projector, and run the shadow comparisons for the agreed observation
   window. The legacy release remains the only rollback target.
4. **Fallback retirement.** After the rollback gate closes, apply kernel
   `0005_single_email_authority` through `0020_delivery_receipts` normally and
   remove the compatibility columns/tables through their owning migration path.
5. **Assembly rebaseline.** `a001_adopt_academy` is an idempotent full product
   baseline: it creates the Academy-owned schema on a fresh database and verifies
   the complete existing contract on an adopted database. Only after that check
   passes is the legacy head unrecorded and its directory removed from active
   `version_locations`.
6. **Normal operation.** The sole migration entrypoint composes the installed
   kernel `versions_dir()` and the Academy assembly directory. Development, CI,
   and deploy all run `alembic upgrade heads`. Static tests require exactly one
   labelled head per active lineage.

`a001` depends on the kernel head, so Alembic may store only the assembly head in
`alembic_version`; that row implies its dependency. Static head attribution and
catalog verification, not an assumed two-row runtime shape, are authoritative.

### Required cutover evidence

Implementation cannot contract or activate the final graph until disposable
PostgreSQL rehearsals prove all of the following:

- the ADR-0017 Sub reference-adopter lineage gate is complete and its reusable
  findings are reflected in Academy's pinned contract;
- fresh kernel-plus-Academy install;
- adoption from a copy at every supported Academy legacy head;
- a PII-free, digest-bound adoption plan whose exact input, approval window,
  maximum row counts, and durable execution receipt are verified before any
  backfill write;
- exact row/count/hash equivalence for people, names, email, active state,
  profiles, credentials, sessions, roles, audit actors, and all 27 classified
  person references;
- zero tenant mismatch, orphan, invalid status, or case-insensitive email
  collision;
- complete PK/FK/index/unique/check/default/nullability contract and exact RLS,
  grants, and absence of unsafe grants;
- the negative control that executing kernel `0003` is destructive and is not
  used by the adoption path;
- drift injection causes the adoption migration to fail closed;
- the real pre-retirement rollback command restores the legacy revision record
  without dropping data, then boots the named fallback release;
- destructive downgrades refuse by default; and
- the final graph resolves `kernel@head` and `assembly@head` to the pinned
  expected revisions with no extra head or root.

Production cutover additionally requires a restorable database backup, recorded
catalog/count evidence, a maintenance window, and an operator-approved release
pair. No target host is inferred by this ADR.

## Rollback and repair

Before fallback retirement, rollback is a controlled authority flip, not an
Alembic downgrade: stop writers, reconcile Party state back to the legacy
projection, verify it, restore the release-specific legacy revision record with
the transitional migrator, then start the named fallback release. Additive
kernel tables remain in place.

After kernel `0005` and the assembly rebaseline, the legacy fallback is retired.
Routine rollback is then limited to code compatible with the active kernel and
assembly heads. Schema faults are repaired forward; `a001.downgrade()` must fail
closed because dropping the adopted Academy schema would destroy product data.

## Consequences

The rebaseline is more work than pointing `version_locations` at two folders,
but it gives each permanent owner one lineage and makes fresh install, adoption,
and rollback testable. UUID preservation avoids a rewrite of Academy domain
facts, while the explicit person-subtype checks prevent an organization party
from silently becoming a learner or instructor.

This ADR authorizes the design and its tests only. Each implementation phase is
a separate, reviewable change with its own PostgreSQL rehearsal evidence; no
schema mutation is included with this decision. ADR 0017's Sub-first lineage
gate must be satisfied before Academy activates the identity lineage transfer.
