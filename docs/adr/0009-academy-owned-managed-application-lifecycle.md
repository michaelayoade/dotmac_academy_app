# ADR 0009 — Academy owns its managed application lifecycle

Date: 2026-08-17 · Status: accepted (owner-directed ecosystem implementation)

## Context

Vendor Control Plane may sell an Academy component and Integrator may execute
an approved deployment command, but neither system owns Academy people,
sessions, enrolments, roles, or account status. A connector that writes Academy
tables or calls an admin-bypass route would create a second decision path.

The Rule-24 inventory found a tested local owner (`app.services.lifecycle`) and
no external service lifecycle port. It also found that Academy is a kernel
application assembly without being a kernel identity-schema assembly. ADR 0007
explicitly deferred its local `Tenant`, `Person`, `UserCredential`, and
`AuthSession` migration. Kernel external identity is typed to kernel `Tenant`,
`Party`, and `AuthSession`, so it cannot honestly bind an Academy `Person`
today.

## Decision

Academy declares product-owned capability `academy.application.lifecycle` at
schema version 1 (wire identity `academy.application.lifecycle.v1`) and exposes
`plan`, `apply`, `observe`, and `cancel` under
`/api/v1/integrations/application-lifecycle/`.

The target is closed:

- `tenant_id`;
- `person_id`;
- `desired_state`, exactly `active` or `suspended`;
- external subject, exactly `provider_binding`, case-sensitive `issuer`, and
  case-sensitive `subject`, with outer whitespace removed.

Email, names, roles, groups, scopes, claims, passwords, employment, enrolment,
and every other field are refused. Integrator transports the command. Academy's
existing lifecycle service owns the account transition and suspension's session
revocation. No provider I/O occurs in Academy's owner service.

The published capability PLAN and APPLY inputs are the desired target document
itself. OBSERVE and CANCEL use declaration-equal identity subsets of that
document. They contain no Vendor/Integrator execution fields: an operation
reference, idempotency key, approval reference or target/plan/state digest is
orchestrator state, not an Academy desired value.

The existing authenticated HTTP port keeps a separate exact-plan ledger
envelope. PLAN persists the canonical target, current product state, their
digests, the action codes, and the resulting plan digest under a tenant-scoped
idempotency key. Those plan fields are database-immutable. APPLY locks the
operation and person, accepts only the exact idempotency key/target/digests,
refuses if the expected state moved, and stores one immutable result. A
same-command retry returns that result without reapplying a state that a later
local decision may have changed. Its OBSERVE and CANCEL requests accept only
the ledger's `operation_ref`, so a caller cannot replace the subject or person
after approval. That adapter envelope is deliberately not the capability
operation input stored in a Vendor `ProvisionStep.input`; the execution engine
owns and supplies it separately. CANCEL is safe only before APPLY; afterward a
new desired state and approval are required.

Requests use the existing timestamped exact-byte HMAC grammar with a distinct
managed-lifecycle key. Empty configuration disables the port. The key is held
by deployment configuration and does not appear in the capability contract;
the contract declares only its secret reference type.

## External identity stop condition

The operation target is evidence, not a login binding. This change does not add
an Academy `federated_identities` table, does not copy kernel binding behavior,
and does not adopt `dotmac-auth-oidc` without the kernel persistence model that
makes `finalize_external_login` and provenance revocation correct.

The capability contract therefore requires activation evidence
`academy.external-identity.binding-ready`. It remains false until a later
authority migration moves Academy identity/session persistence to the kernel or
the kernel gains an approved typed seam that preserves one owner. That later
slice must migrate existing accounts and sessions, run the kernel lineage,
adopt the published OIDC adapter with a shared atomic StateStore, and prove
exact issuer/subject binding plus provenance-bound revocation. It may not add a
shadow table as an interim shortcut.

### Amendment — 2026-08-17

ADR 0010 supersedes this stop condition. The approved seam is an
Academy-local binding and session-provenance owner, not a migration into another
application's kernel tables. The managed target now becomes the binding during
APPLY, and the published protocol adapter supplies only a verified exact
issuer/subject. The rest of this ADR — product lifecycle ownership, exact plans
and Integrator as transport — remains accepted.

## Consequences

- The managed application port is useful and retry-safe for existing local
  account status, but the Academy component is not SSO-activatable yet.
- Integrator owns the cross-system command and signed receipt; Academy owns only
  its local immutable plan/result evidence and account transition.
- A person missing from the exact tenant is a stable refusal, never JIT
  provisioning. The external subject is never matched through email.
- Applied state has no automatic rollback. Reversing it requires another exact
  plan and approval, preserving intervening Academy decisions.

## Verification

- service and API tests cover same-key replay, changed-content conflict, exact
  plan application, expected-state drift, session revocation, observe/cancel,
  forbidden fields, and exact-byte authentication;
- a PostgreSQL canary checks cross-tenant RLS and a raw update proves plan-field
  immutability;
- an architecture guard forbids provider I/O and identity writers in the owner
  service;
- the canonical contract and all eight self-contained JSON Schemas are parsed
  by kernel a68's `CapabilityContractSnapshot` / `CapabilitySchemaDocument`,
  with every schema identity and byte digest cross-checked; an architecture
  sensitivity proves no orchestration-envelope field can re-enter a capability
  input. This is checkout evidence until Academy advances its released a38
  dependency pin.
