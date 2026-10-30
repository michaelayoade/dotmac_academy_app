# Prepared canonical identity storage

Source only. No caller is wired by this capsule, and no authority, canonical adoption, installed qualification or writer retirement is established. All new tests are authored for hosted PostgreSQL and have not run.

`app/services/canonical_identity_store.py` uses public Kernel106 models and Academy's existing profile extension. It exposes detached typed facts and granular storage operations. Facts, catalog tuples, UUIDs and database handles are observations or inputs, never authorization evidence. Mutable JSON is deep-copied; the fact dataclass does not promise deeply immutable JSON.

The actual private owner must resolve genuine tenant and provenance, establish its caller root/savepoint, validate policy and eligibility, lock all existing participating Party rows in sorted UUID order, reobserve target resolution, and refuse drift. Missing IDs remain absent in the returned tuple. Newly created local Party rows belong to the creating transaction. No method starts/commits/rolls back/retries a transaction, reads a clock or Settings, authorizes a user, creates credentials, or touches sessions, bearer material, account tokens or audit.

## Operations and caller preconditions

- `find_party_exact_email` retains admissions exact equality. `find_party_normalized_email` compares `lower(btrim(Party.email))` to the caller's already normalized value. Neither normalizes its input or proves person eligibility. Owner separately requires canonical subtype/profile. Exact misses never fall back to normalized reuse; uniqueness failures propagate.
- `lock_parties` sorts and deduplicates existing Party IDs. `lock_person`, `lock_profile`, `lock_roles`, and `lock_grants` remain separate so owner-specific secondary-lock order is unchanged. Every query has an explicit tenant predicate, including subtype reads through Party. Refreshing queries can overwrite cached state, so owner must not use them to discard unflushed work.
- `create_person` requires every caller-decided value: UUID, tenant, email, display name, names, activation, custom fields, profile status/avatar/preferences, and timestamps. PartyType.person is the structural operation type. It preserves three flushes: Party, subtype, profile. No normalization, activation decision, projection, validation rule, collision handling or reuse is added.
- `provision_missing_roles` takes the caller's freshly locked same-transaction catalog and validated configured names plus explicit missing-role IDs/timestamps. It adds missing slugs in sorted order, preserving names/custom roles. Catalog tenant/duplicate shape checks are not authority. The caller must supply a complete fresh catalog; stale facts cannot establish absence. Unique races propagate without retry. The returned tuple retains input catalog order with additions appended.
- `ensure_grant` requires the caller-held Party lock and a previously admitted scoped role. It locks the exact membership, adds only if absent, and flushes only for creation. The caller supplies new ID/timestamps; existing rows remain unchanged. Foreign keys and RLS remain authoritative.
- `credential_member_ids` reads and locks all credential IDs for the tenant/Party, with no alias, account status or policy filter. Any nonempty result suppresses invitation issuance. It reads no credential material. The caller must hold the common Party lock even for empty membership, and **every membership writer must participate in that lock**. This helper cannot inspect PostgreSQL lock ownership; it makes no verified-lock claim. A fact alone cannot authorize issuance.

## Later integration boundaries

Invitation issuance currently locks sorted Party → subtype/profile → Role → Grant → AuthSession → credential/policy/token membership. Web assignment currently locks Party → subtype/profile → AuthSession → Role → Grant. Granular operations preserve those differing orchestrations. Owners retain their private authorization checks, clock sampling after waits, exact revalidation, role admission, alias synchronization, token/hash/credential mechanisms, audit and error mapping.

Invitation creation uses public `person_display_name` without stripping and explicit name limits; web creation uses a stripped projection. Kernel `normalize_email` lowercases only, while Academy also strips. Those decisions remain at callers. Existing identity/profile/status/activation/custom fields/grants must not be changed on reuse.

Onboarding is not implemented here. Its received bearer and host tenant must enter the existing invitation owner through a private onboarding context, reprove the Applicant hash under Party → Applicant → task locks, and require task writers to participate in the Applicant lock. No synthesized Request, administrator, session or public proof boolean is permitted.

## Qualification

New tests reuse the actual `current_account` canonical fixture and non-bypass `app_user` PostgreSQL sessions. They cover explicit values and three flushes, exact versus normalized lookup, genuine uniqueness failure, rollback after each creation flush, tenant-scoped reads, credential membership, additive/idempotent roles/grants, and independent-root lock waiting. They deliberately do not claim full all-writer participation or invitation authorization. Hosted installed Kernel106/canonical migrations/RLS/ACL and full regression qualification remain required. The base222 files are unchanged; future credential-proof APIs are a separate gate.


### 2026-10-19 source amendment: independent identity prerequisites

The paired future Kernel V4 comparison is now called by Academy's genuine
historical import adapter. Before Kernel writes, the exact single-use decoder
captures immutable source rows and complete product profile/policy projections.
The existing private product handle registers that decoder, Connection, root,
XID, original expectations, installed composition inputs and canonical target
OIDs. After actual inserts, Kernel independently compares its nine canonical
targets and current audit rows, while Academy compares every profile/policy
field and complete extent. A new decoder re-reads historical values against the
original capture; observed targets never become expectations.

The returned actual receipt identity is bound privately after comparison and
retains the existing token association tuple. Identity observation, both sides
of immediate a003 receipt observation, and both sides of Learning V5 sealing
recheck this association. Caught failures poison the existing product/Unit3
context; disposal drops the captured material. Standalone import still performs
the same data comparisons but issues no product authority. A public successful
Kernel comparison or copied receipt cannot advance the private phase.

Kernel's reused catalog checks remain bounded; this is not a full retained RI
seal or a004 implementation. Initial real Schema/Environment qualification
remains required. `retained_schema_unverified=True` and the terminal phase
`Learning sealed, retained adoption pending` remain truthful. Fresh genesis,
a004/a005, sole commit, actual runtime custody, Integration/ERP delivery and
new-fact-preserving forward recovery are still pending. These partial source
capsules require genuine full pinned baselines and unreleased owner composition;
new canaries are authored, not run. No successful final admission is claimed.
