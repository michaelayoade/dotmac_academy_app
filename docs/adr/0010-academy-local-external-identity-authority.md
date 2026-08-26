# ADR 0010 — Academy-local external identity and session authority

Date: 2026-08-17 · Status: accepted (supersedes ADR 0009's external-identity stop condition)

## Context

ADR 0007 made Academy a kernel **runtime** assembly and explicitly deferred
its identity-schema migration. ADR 0009 then made the correct stop decision:
its managed target was evidence only because neither a kernel schema migration
nor a typed local owner existed. Treating that target as a login binding would
have created a second identity writer.

The platform boundary is now more precise. Applications are independent and
own their databases, sessions and authorization. Importing Starter's
`Party`/`AuthSession` ORM or running its identity lineage in Academy would make
two applications share persistence rather than compose through contracts. The
safe cutover is therefore not a cross-application schema migration. It is one
Academy-local owner with the same security invariants and no protocol logic.

The published `dotmac-auth-oidc` 0.1.0a1 adapter already owns discovery, PKCE
S256, asymmetric ID-token verification, audience/issuer/nonce validation and
the provider-neutral `(issuer, subject)` result. It owns no local rows and
issues no session, so consuming it does not move Academy's authority.

## Decision

Academy remains the sole owner of its `Tenant`, `Person`, `UserCredential`,
`ExternalIdentityBinding` and `AuthSession` rows.

- A local binding is keyed by exact, case-sensitive
  `(tenant_id, provider_binding, issuer, subject)`. Only outer whitespace is
  removed. The same local registration may bind a person at most once.
- Binding is an administrative, evidenced action over an existing person. A
  login never provisions a person, matches an email/name, or imports provider
  roles, groups, scopes, organization or entitlement claims.
- A disabled row remains in place and retains the tuple. Re-enabling the same
  person's row does not resurrect any session; assigning its subject to a
  different person is a conflict.
- `finalize_external_login` locks the binding and then the person, re-checks
  both while locked, and calls Academy's existing session issuer inside the
  same transaction. The session stamps the binding id as provenance.
- Disablement takes the same binding lock and revokes exactly the live sessions
  that cite it. `ON DELETE RESTRICT` preserves known provenance: NULL means a
  password session, never a binding that was erased after issuance.
- Account suspension remains the broader Academy lifecycle decision and
  revokes all sessions for that person. Every authenticated refresh validates
  session expiry/revocation, active account state and active binding state.
- The ceremony store is an Academy table using a hashed opaque state id and a
  single `DELETE … RETURNING` consume. It is shared across all workers, tenant
  isolated with forced RLS, and bound to the existing request transaction.
- `dotmac-auth-oidc` is exact-pinned at the published `0.1.0a1`. Academy
  contains no local discovery, JWKS, token-exchange or ID-token verifier.

The managed `academy.application.lifecycle.v1` owner now binds or disables the
exact approved subject as part of APPLY and reports `active` or `disabled`
binding state. Its required `academy.external-identity.binding-ready` check is
still not a constant: a deployment reports it true only after this migration
and code are installed and its provider registration is complete. An absent or
partial OIDC configuration keeps the login surface disabled/fail-closed.

Academy also owns the value-free composition
`academy.identity-user-binding.v1`. It permits only the public `/issuer_url`
and immutable `/subject` from an exact `identity.user.lifecycle.v1` APPLY
receipt to populate the corresponding nested Academy APPLY target. It does not
map `provider_binding`: that remains Academy's installed local registration and
APPLY corroborates its exact binding+issuer pair before any binding mutation.
The source contract is pinned by exact schema identity and digest, so Vendor
cannot replace the provisioned receipt with caller-copied values.

The composition JSON is canonical a69 grammar. Academy still runs kernel a38,
so typed cross-contract validation and deployment activation remain fail-closed
until kernel a69 and `dotmac-managed-identity` a1 are published and Academy can
pin their released wheels. The checked-in artifact is the product decision,
not a claim that those unpublished dependencies already exist.

## Transaction order and races

External login and binding disable both lock the binding row. Login then locks
the person. An account-only suspension locks the person and never waits back on
the binding, so it can complete, revoke sessions and make a waiting login
re-read `suspended`. Managed binding APPLY takes the binding path before the
account transition, preserving the same order.

No service commits. Kernel request boundaries remain the one transaction
authority; their commit makes binding evidence, account state and session
effects visible together or not at all.

## Authority and rollback

There is no shadow or dual-write phase. The pre-cutover release has no working
external login, so rollback is the prior application release plus migration
downgrade before any binding/session provenance rows exist. Once used, rollback
requires an explicit data-preserving plan; dropping bindings would erase login
authority evidence and is not an operational fallback.

This decision supersedes only ADR 0009's deferred external-identity section and
ADR 0007's assumption that the eventual answer must migrate Academy identity
to kernel tables. Their runtime-assembly and product-lifecycle ownership
decisions remain accepted.

## Verification

- service canaries cover exact case-sensitive binding, disabled-tuple
  retention, provenance stamping, selective disablement, suspension, re-enable
  and refresh refusal;
- PostgreSQL canaries cover cross-tenant RLS and the composite
  person/binding/session foreign key;
- state-store canaries cover hashing, atomic single-use and provider-binding
  mismatch;
- architecture ratchets forbid Starter identity models, provider clients and a
  local verifier, pin the adapter release, and require the shared binding lock
  on login and disable paths.
- capability-input ratchets keep Vendor/Integrator operation references,
  approval/idempotency values and plan/state digests outside Academy's desired
  document, while the identity composition terminates directly at
  `/external_subject/issuer` and `/external_subject/subject`.

These tests must run through Observer at the exact commit; local test execution
is not evidence under this repository's current policy.
