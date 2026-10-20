# ADR 0009 — Kernel Identity and Migration-Lineage Cutover

**Status:** Accepted; schema implementation is gated by the rehearsals below  
**Date:** 2026-08-11  
**Source revalidated:** 2026-10-17 at Academy `61f69194d6591c6a2d13472a5e38c3a5ecf34454`  
**Implementation:** `design_only`; activation evidence is `pending_external_evidence`  
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
- Twenty-eight Academy columns carry human identity. Twenty-four say `person`
  in the column name; `attempt_grants.granted_by` and
  `success_queue_entries.assigned_to`/`resolved_by` and
  `lab_operations.requested_by` are the four semantic aliases. Eleven currently
  have physical foreign keys to `people`; seventeen are logical references only.
- Academy and kernel both ship revision `0001_initial_tenant_schema`. Their DDL
  functions are AST-equivalent, but two files declaring the same revision make
  a composed Alembic graph fail before it can run.
- Kernel revision `0003_party_identity` is explicitly destructive: it was
  written for an empty starter and drops `people`, `person_roles`,
  `user_credentials`, and `auth_sessions`. It must never run directly over
  Academy's populated legacy identity or destroy that data. The unchanged
  revision must still execute in genuine independently owned Kernel history
  through the separately rehearsed canonical-entry mechanics.

The current Academy lineage also mixes platform tables and Academy product
tables in one numeric chain. Keeping that chain as the permanent assembly
lineage would preserve the original ownership ambiguity and would make
branch-aware rollback unreliable because its root is also the kernel root.

This refresh continues the accepted design in existing PR #122; it is not a
new decision awaiting acceptance or an implemented cutover. Its initial commit
`2d9506f` counted 27 references (11 physical, 16 logical) and ended the Academy
chain at `0053_entrance_defaults`. The prior source checkpoint at `a99a395e`
counted 28 and ended at `0060_lab_conditional_ops`. Current revalidation at
`61f69194` retains 28 references (11 physical, 17 logical) and ends at
`0061_lab_completion_grants`; PR #177 adds grants over existing identity columns.
The current lineage head is now `0062_lab_template_access`, an additive
`lab_templates.access` JSONB column with a constant default; it touches no identity
column, so the reference census above is unchanged.
These are source coordinates only; no
production database, rollout or rehearsal result is inferred from this census.
ADR 0008 is now the accepted lab-worker-role decision; this identity proposal
uses ADR 0009 and preserves that current document.

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
| Schema and lineage adoption | Starter's `a001_adopt_custom_field_definitions` create-or-adopt product baseline and PostgreSQL migration rehearsals: full catalog/RLS/grant verification, drift rejection and destructive-downgrade refusal | Starter is not a runtime identity system of record; product-baseline adoption does not authorize stamping or skipping canonical Kernel revisions |
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

Accepted Starter ADR 0017 now separates the two persistence planes. Its general
platform/P11 gate is **met** by Vendor Control Plane production evidence, as
recorded in `dotmac_starter_mt/docs/inventories/p11-adoption-status.md` and the
2026-08-17 amendment to ADR 0017. The earlier fleet-wide implementation
moratorium is not today's blocker. That evidence does not prove Sub's tenant
plane or Academy's identity adoption.

Sub remains the tenant-plane-1/RLS reference adopter. Its expected first failure
at `0001_initial_tenant_schema`, documented in
`dotmac_starter_mt/docs/inventories/sub-lineage-dispositions.md`, remains a
separate `pending_external_evidence` gate here. Academy may design its adapter
and rehearsals, but must not activate identity lineage transfer until that
tenant-plane evidence and reusable findings are incorporated. Partial canaries
on later revisions do not satisfy the atomic root/RLS/GUC contract. Academy
adds no speculative kernel identity-adoption SDK, facade or shadow binding.

If the Sub gate advances the required kernel revision beyond Academy's pinned
version, Academy updates and validates that dependency in a separate adoption
change before changing this ADR's lineage endpoints. It does not silently
substitute a newer head during a database cutover.

True Kernel Party/person-facet contracts and their validated **published** floor
are required before runtime adoption. The checked-in `0.1.0a38` pin and
`0020_delivery_receipts` endpoint below remain exact current source/design
coordinates; they do not prove that future contract. Selection of the future
floor is unresolved. In particular, later Kernel ADR 0019's RBAC rename from
`party_roles` to `party_role_grants` must be reconciled against that selected
release rather than silently replacing the a38 `PartyRole` spellings below.
Any resulting endpoint/catalog conflict must be resolved explicitly before
implementation. The accepted final independent `a001_adopt_academy` assembly
strategy is unchanged.

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
- The four actor/requester/assignee aliases (`granted_by`, `requested_by`,
  `assigned_to`, `resolved_by`)
  also retain their UUIDs and human semantics. They are explicitly inventoried
  so a name-based scan cannot hide them from the shadow and orphan checks.

`lab_operations.requested_by` was introduced by `0055_lab_operations` as a
nullable Person UUID without a foreign key. User-triggered requests supply the
person's UUID; automated worker/reconciler requests supply NULL. Preserve both
human attribution and valid NULL automation through adoption. In contrast,
`lab_operations.claimed_by` is a worker fencing string, not a Person reference;
it and its host/epoch decomposition do not enter the human-identity census.

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

The accepted final assembly strategy has two independently owned roots. Its
dependency must truthfully name the selected published Kernel head after that
entire canonical chain has actually executed:

```text
kernel:   0001_initial_tenant_schema -> ... -> <installed canonical Kernel head>

assembly: a001_adopt_academy -> a002 -> ...
          down_revision = None
          branch_labels = ("assembly",)
          depends_on = <that same actually executed Kernel head>
```

The existing numeric Academy chain (`0001` ... `0061` at source revalidation,
originally `0001` ... `0053` in PR #122, followed by future bridge revisions) is
a temporary `academy_legacy` lineage. Those recorded IDs are not relabelled or
reparented. Selecting the installed Kernel file for the shared `0001` ID cannot
turn an existing Academy version row into genuine Kernel execution history;
AST-equivalent DDL and catalog existence are insufficient. The Kernel requires
its own genuine independent history and owning connection. No canonical
Kernel revision may be stamped, existence-skipped, deferred past runtime
cutover, rewritten or replaced by a facade.

**Historical and superseded bridge.** Initial PR #122 used a38 coordinates
ending at `0020_delivery_receipts`, proposed stamping `0003_party_identity`
after verification, selected one shared-root file, and postponed `0005` through
`0020` until after runtime cutover. That bridge is rejected under the current
immutable/full-canonical-lineage requirement. These coordinates remain in the
historical inventory for traceability, not as an executable option or accepted
entry algorithm. Verification does not make a Kernel stamp permissible.

**Canonical entry algorithm: unresolved.** A separate proposal and PostgreSQL
rehearsal must prove execution of the entire unchanged installed Kernel chain
on its owning connection with genuine independent history, without destroying
legacy identity. This document selects no escrow executor or other mechanics,
grants no operational authority, and changes no released DDL or lineage rows.

1. **Legacy expand.** Preserve all data and behavior needed by the named
   fallback release, including Academy profile and login-security state.
2. **Canonical entry gate.** Through the separately reviewed entry algorithm,
   execute the full unchanged installed Kernel lineage to its actual canonical
   head. Prove lossless identity import, UUID/tenant/person-facet mappings,
   source-writer closure, catalog/RLS/grants, fallback safety and durable
   execution evidence. Existing legacy tables or version rows cannot satisfy
   a missing revision. Failure leaves runtime authority with legacy Academy.
3. **Runtime cutover.** Only after the actual canonical head, identity mapping,
   published-floor and external gates pass, flip the one-way projector and
   runtime readers/writers. Preserve the named fallback release throughout the
   observation/rollback window.
4. **Fallback retirement.** After that window and its evidence gate close,
   retire only Academy's product-legacy compatibility state through its owning
   migration path. No Kernel revision remains deferred to this phase.
5. **Assembly rebaseline.** `a001_adopt_academy` is an idempotent full product
   baseline: it creates the Academy-owned schema on a fresh database and verifies
   the complete existing contract on an adopted database. Only after that check
   passes may the separately reviewed product-history transition retire the
   legacy directory from active `version_locations`. This cannot manufacture
   or replace canonical Kernel history. The accepted `a001_adopt_academy`
   strategy remains; its dependency must be the actual selected Kernel head.
6. **Normal operation.** The sole migration entrypoint composes the installed
   kernel `versions_dir()` and the Academy assembly directory. Development, CI,
   and deploy all run `alembic upgrade heads`. Static tests require exactly one
   labelled head per active lineage.

`a001` depends on the kernel head, so Alembic may store only the assembly head in
`alembic_version`; that row implies its dependency. Static head attribution and
catalog verification, not an assumed two-row runtime shape, are authoritative.
This graph dependency is not proof of execution: the full unchanged Kernel
chain and its genuine independent history still require their own evidence,
even when Alembic compacts the final recorded heads.

### Required cutover evidence

Implementation cannot contract or activate the final graph until disposable
PostgreSQL rehearsals prove all of the following:

- the ADR-0017 Sub tenant-plane reference-adopter lineage gate is complete and
  its reusable findings are reflected in Academy's pinned contract;
- fresh kernel-plus-Academy install;
- adoption from a copy at every supported Academy legacy head;
- a PII-free, digest-bound adoption plan whose exact input, approval window,
  maximum row counts, and durable execution receipt are verified before any
  backfill write;
- a published Kernel Party/facet floor is selected and separately validated,
  including the RBAC spelling/catalog and lineage-endpoint reconciliation;
- exact row/count/hash equivalence for people, names, email, active state,
  profiles, credentials, sessions, roles, audit actors, and all 28 classified
  person references;
- zero tenant mismatch, orphan, invalid status, or case-insensitive email
  collision;
- complete PK/FK/index/unique/check/default/nullability contract and exact RLS,
  grants, and absence of unsafe grants;
- the negative control that running Kernel `0003` directly over populated
  legacy identity is destructive; the genuine canonical-entry path instead
  executes every unchanged revision in its independently owned history without
  legacy data loss, and refuses stamping, existence-skips or substitute rows;
- drift injection causes the adoption migration to fail closed;
- the real pre-retirement rollback restores the named legacy release and
  product-owned state without dropping data or changing genuine Kernel history;
- destructive downgrades refuse by default; and
- the final graph resolves `kernel@head` and `assembly@head` to the pinned
  expected revisions with no extra head or root.

Production cutover additionally requires a restorable database backup, recorded
catalog/count evidence, a maintenance window, and an operator-approved release
pair. No target host is inferred by this ADR.

## Rollback and repair

Before fallback retirement, rollback is a controlled authority flip, not an
Alembic downgrade: stop writers, reconcile Party state back to the legacy
projection, verify it, and start the named fallback release using the separately
rehearsed product-history procedure. Genuine Kernel execution history is never
rewritten or stamped to simulate rollback. Canonical Kernel state remains in
place.

After the observation/rollback window and assembly rebaseline, the legacy
fallback is retired. The complete Kernel chain already ran before runtime cutover.
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
schema mutation is included with this decision. General Vendor P11 completion
does not satisfy ADR 0017's separate Sub tenant-plane gate or Academy's own
identity/facet/published-floor gates. Those must pass before Academy activates
the identity lineage transfer.

## Amendment — 2026-10-17: account state and canonical-entry rehearsal

Academy's account status and Kernel identity activation are separate facts.
This amendment supersedes the earlier mapping
`Party.is_active = (people.status = 'active')`. Preserve the exact recognized
legacy account status in Academy-owned account state keyed by tenant and Party
UUID. Account suspension continues to govern the existing product policies;
it must not silently activate or deactivate the canonical identity. Importing
`Party.is_active` requires explicit, justified identity-activation provenance.
An absent activation disposition blocks import; neither an implicit active
default nor an inference from account status satisfies that requirement.

The next canonical-entry rehearsal will preserve the eight colliding legacy
relations (`tenants`, `tenant_domains`, `people`, `user_credentials`,
`auth_sessions`, `roles`, `person_roles`, `audit_events`) and their genuine
`alembic_version` table in a schema owned by the Academy host. The proposed
fixture uses a caller-owned migration connection and transaction, then executes
the entire unchanged installed Kernel directory into its canonical namespace
with new, genuine migration history. It must prove preservation of original
relation identities, rows, incoming foreign-key targets, privileges and legacy
version rows, and complete rollback after injected failures. Cluster roles are
not relocated. Canonical heads alone are insufficient evidence: retain actual
per-revision execution and immutable migration-source evidence.

This is a rehearsal candidate, not a selected or qualified production entry
executor. The inventory remains `design_only`, canonical entry remains
`unresolved`, and the installed historical a38 coordinates remain historical.
The production Alembic environment, dependency pins, identity writers and
runtime assembly do not change through this amendment. The actual published
floor, Sub tenant-plane findings, complete import, catalog-exact reference
rebinding and populated rollback gates still precede activation.

The fallback must be a named compatibility release whose behavior is proved
against the resulting schema. Do not promise that the unmodified old binary
can run after canonical identity entry. A fallback that restores legacy domain
writers while retaining genuine Kernel identity/auth authority must reconcile
accepted new inserts, updates, events, ACK state and deletions before the writer
flip. If identity authority is also reversed, first prove that every accepted
new canonical fact is representable, including longer names/email, credential
multiplicity, grants and deletions. Neither an old snapshot nor an insert-only
copy establishes that safety. No fallback activation or retirement is claimed.
