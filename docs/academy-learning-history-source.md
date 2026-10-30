# Historical Learning source capture

This source-only reader is a prerequisite for populated adoption. It performs
no canonical writes, DDL, transaction commit/rollback, fixture replay, package
installation, source publication, or runtime activation. All tests are authored
and **not run**.

The fixed historical source is `public`, all twenty-seven Learning tables from
the actual a5 model Git blobs, and the genuine frozen sixty-two migrations
(maximum numbered revision 0061, with date-prefixed revisions). The actual
schema has 47 tables: 27 Learning, 8 legacy identity, and 12 retained product.
The adapter neither uses the unmerged ERP checkpoint model/draft0062 nor adds
tenant fields to the five already tenant-scoped assessment tables.

There are 261 source fields. Every one participates in independent raw
readback. Released `LearningSnapshotV5` row contracts hold the 260 module fields.
The full `(tenant_id,id,erp_synced_at)` completion cohort, including NULLs,
remains a separate private product observation for a later NEW checkpoint
transfer. No undeclared field is attached to module DTOs. JSONB travels as
PostgreSQL text, float8 as exact send bytes, and timestamptz as exact microsecond
instants; unsupported datetime representations refuse. No Python JSON parsing,
float conversion, clamping, defaulting, stripping, casing, or field truncation
occurs. Rows are ordered by native UUID as in released snapshot storage APIs;
all stored order columns are preserved unchanged.

`_capture_learning_history(connection)` issues an opaque private handle on the
actual caller-owned app_admin Connection and active root, including PostgreSQL
physical transaction ID continuity behind SQLAlchemy's logical root. It admits only the
fixed historical catalog, locks its deterministic 27-source + tenant/people +
legacy version-table subset, and captures complete OIDs, columns/default
expressions, keys, actual ordered FK endpoints/actions, incoming references,
indexes/predicates, RLS/policy dependencies, ACLs, rules, triggers, role posture,
all real tenant members (including empty Learning tenants), person references,
all source rows and product ACKs. Native complete tenant extent is read from the
genuine source tenants; no caller tenant tuple can shrink it. No historical
missing-table or missing-tenant state falls back to fresh storage. A zero-tenant
historical store refuses V5's nonempty extent contract; a genuinely fresh path
requires a separate future coordinator's explicit catalog-absence admission.

The external coordinator must fence/drain writers and preacquire its complete
source/identity/retained/version lockset in deterministic order BEFORE composing
these stages. The adapter's subset lock is not a lasting fence and does not
justify later out-of-order locks. The existing hosted fixture replays all 62
unchanged migrations, including genuine0056 autocommit blocks, before beginning
this single-root source/adoption phase.

`_export_learning_history`, `_completion_ack_history`, and
`_verify_canonical_learning_history` require the exact privately issued handle,
Connection, and still-active root. A copied handle, public V5 snapshot or public
verification/import observation grants no completeness or DDL authority. The
canonical verifier delegates to the real released `verify_snapshot_v5` and
checks source stability on both sides; it never imports or manufactures a
successful observation. `_release_learning_history` removes private retained
material without touching the caller's transaction. Call it in a coordinator
`finally` before closing the connection.

Source proof survives only the narrowly expected same-OID identity namespace
move from `public` to `academy_identity_compat`. It requires the existing
product account-token adapter's private exact-root capture and the actual
successful identity-import hook's exact expected/receipt association, bound to
this capture's tenant/people OIDs and full cohorts. Call the explicit private
`_observe_identity_relocation` after actual identity import and BEFORE the
immediate a003 receipt consumes the token owner's state. That step retains the
exact genuine expected/receipt association in this capture's private Connection/
root context, continuously reproving its identity catalog and cohorts. It accepts
no caller receipt. Caller namespace overrides,
booleans, and public receipt DTOs are not accepted. Identity parents' own
columns/keys/outgoing references/index/security/cohorts are captured. Their
incoming token/retained FKs and associated internal RI triggers are owned by the
actual identity/token/whole-product coordinator, allowing genuine a003 without
duplicating its authority. All 27 Learning source catalogs retain their FULL
incoming reference evidence. Consume/end this source phase BEFORE later a004
changes the two applicant incoming references; the whole-product coordinator
must independently prove those declared deltas and final catalog.

Tests use genuine frozen62 storage and actual app_admin/root, seed every source
field across two tenants plus an empty Learning tenant, preserve nullable ACKs,
and cover raw values, catalog/role/reference/RLS refusals, root/Connection/handle
bindings, late source drift, genuine identity-import relocation and late failure
rollback of real canonical identity DDL/copies. The positive harness extends
that SAME Connection/root through actual a003, immediately captures its genuine
receipt (which disposes the other owner's private state), and then applies the
full real installed Learning lineage before public V5 import and independent
canonical verification. It uses complete installed Kernel/Learning directories
plus the Academy identity directory, explicit staging, and the actual a1/f674
public prerequisite bindings: tenant scope + module roles → Kernel0001,
party-person → Kernel0003, tenant audit → Kernel0029. No provider revision or
fixture/API is invented. Positive and late source/canonical-failure rollback
canaries are AUTHORED NOT RUN, not installed qualification.

Future hosted qualification still requires the real installed successor Kernel,
published Learning floor, complete original fixture/source collection and full
Academy owner/model/FK assembly. Actual checkpoint creation/transfer, full owner
adoption, final catalog/fence evidence, fresh/populated recovery and every
remaining retirement gate remain outside this reader. Presence of the source
harness is not proof that those installation or adoption gates have passed.
