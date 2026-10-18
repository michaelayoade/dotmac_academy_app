# Historical retained schema: private intermediate contract

This is a source-only structural contract for eleven retained tables in their
historical **public** namespace, before identity relocation. It excludes
`account_tokens`, which belongs to a003. It performs no DDL, migration execution,
namespace rebinding, adoption consumer wiring, receipt issuance or activation.
The product evidence module still reports `retained_schema_unverified`.

The verifier ALWAYS raises `RetainedSchemaUnsupported` after the structural and
security checks pass. A structurally wrong catalog instead raises the base
`RetainedSchemaRefused`. Neither result authorizes a004, proves complete schema
correctness, qualifies the product, or grants ERP authority. There is no caller
proof DTO, boolean, namespace selector, expected override or capture equality
shortcut. No successful private handle is issued in this intermediate slice.

## Immutable source lineage

The contract was derived by stdlib AST/text inspection of the genuine actual-a5
096 fixture, not current ORM definitions or a captured target database:

- Original source: `tests/fixtures/kernel_identity_entry/alembic/versions` in the
  independently verified frozen a5 source closure.
- Manifest SHA256:
  `0c6f477bcdb8477a6e34c6b15809f71f7382c2cc8ce3b43e72c387daa6879a37`.
- Complete set: 62 migration files, highest revision `0061_lab_completion_grants`.
  No draft 0062 is historical evidence.
- `_FROZEN62` pins the entire exact filename/size/SHA256 set; `_DDL_LINEAGE`
  identifies applicable creation, addition and grant/index/check revisions.
- Date-prefixed `20260711_0034_entrance_resilience.py` and
  `20260711_0035_applicant_profile.py` are the actual filenames.

There are 166 columns, 21 primary/unique constraints, 17 foreign keys, four
checks and 49 indexes in the fixed structural projection. Column tuples retain
physical order, SQL type, nullability and projected default expression. The
source SQL expressions for partial indexes and checks remain explicit constants;
these are not represented as PostgreSQL rendering qualifications.

| Family | Required historical semantics |
| --- | --- |
| applicants | All 49 columns through0052; tenant CASCADE; two composite Learning references NO ACTION;0052 partial tenant/email uniqueness for NULL external_ref and tenant/external_ref uniqueness for non-NULL external_ref. No person_id or cohort_id standalone FK. |
| email_outbox | Tenant CASCADE; tenant/id and tenant/idempotency keys; worker SELECT/INSERT. |
| lab_templates | Tenant CASCADE; global activity uniqueness; nullable0054 instructions_md. No course/activity FK. |
| lab_instances | Tenant CASCADE; global instance_name unique; validated runtime_presence check/default absent. No activity/person FK. Web INSERT only six request columns; worker SELECT/UPDATE. |
| lab_operations | Tenant CASCADE and internal composite instance CASCADE; one open operation per instance; all0056/0060 checks validated; nullable0059/0060 claim/conditional fields. Web INSERT only five request columns; worker SELECT/INSERT/UPDATE. No requested_by FK. |
| notifications | Tenant and composite person CASCADE; worker SELECT/INSERT. |
| onboarding_tasks | Tenant CASCADE and internal composite applicant CASCADE; applicant/key uniqueness. |
| platform_settings | Global key/value table; no tenant column/FK, no RLS/policy; web SELECT, platform CRUD, worker SELECT. |
| tenant_entrance_defaults | Tenant PK/FK CASCADE; nullable defaults and no default_bank_id FK. |
| reminder_log / reminder_preferences | Tenant and composite person CASCADE; historical occurrence/person keys and defaults. |

All ten tenant tables require enabled AND forced RLS and the single permissive
PUBLIC, all-command tenant-isolation policy. Checks require validation and all
constraints remain nondeferrable and initially immediate. For these ordinary
tables, primary/unique/foreign-key constraints require `connoinherit=true`; the
four CHECK constraints require `connoinherit=false`, since frozen DDL never
declares `NO INHERIT`. Index
structure requires exact names/keys/uniqueness/primary flags, valid-ready-live,
btree, no expressions, INCLUDE keys, ordering options or extra indexes.

## SQL normalization and security boundary

The intermediate verifier does **not** strip casts, parentheses, whitespace,
collations or operators to pretend two SQL expressions are equivalent. It checks
fixed simple null predicates and tenant policy expressions exactly. Other
rendered checks, the lab-operation IN/ANY predicate, projected default renderings,
and default opclasses/collations require a separately reviewed hosted frozen62
oracle. Check names/validation and index structure alone cannot prove their
expressions, which is why the final unsupported gate is unconditional.

The actual connection must be PostgreSQL/psycopg, app_admin, inside one active
nonnested nonautocommit root with parameter hiding and logging disabled. All
relations must actually belong to app_admin. The verifier reads real pg_roles,
role memberships, table/column ACLs AND effective table/column privileges. It
requires nonsuperuser roles, bypass only for admin/worker, no role creation,
database creation, replication or role-level configuration, a NOINHERIT worker
and no memberships involving the four examined roles. Explicit source grants do
not substitute for effective privilege checks. Extra table/column/PUBLIC grants,
worker-state web grants, or missing grants are structural refusals. Full cluster
security qualification, tenant-function dependencies/definition and ambient
schema authority remain part of the unsupported hosted gate.

`_observe_historical_catalog(connection)` is a pure private read-only catalog
projection suitable for the hosted review packet. It accepts no namespace and
reads no table data, row counts, row digests, credentials or role configuration
values. It includes actual OIDs, expressions, opclasses/collations, policy
dependencies, function source hash, ACLs and effective privileges. Its returned
dictionary is constructible data and is NEVER accepted as admission evidence.
It does not log or print. A hosted test may serialize this packet from the
immutable frozen replay, paired with the complete source inventory. That packet
is a candidate source oracle, not a production receipt and never expected=observed
on the database being adopted.

Before successful proof issuance can be implemented, the owner must review the
source-bound PostgreSQL packet, close every rendering/security gate, author and
run expression/role canaries, and establish complete ordered locks/fence and
actual Connection/root/physical-XID continuity. Future post-relocation endpoint
rebinding needs genuine private phase evidence owned by product/a004. This
historical module does not accept a caller override to simulate that phase.

## Hosted checks: authored, not run

`tests/test_academy_retained_schema.py` imports only SQLAlchemy, stdlib, pytest,
this private module, the genuine fixture's `rehearsal` helpers and
`tests.test_kernel_identity_entry.legacy_engine` / `entry_transaction`. The three
new files can be overlaid onto actual a5 for focused qualification without
future Kernel/Learning API imports. The real fixture provisions an EMPTY
`KERNEL_ENTRY_DATABASE_URL`, asserts hosted CI and pre-existing real roles, sets
session ROLE app_admin, verifies the manifest and executes all62 real files via
Alembic, including genuine autocommit blocks. Tests roll back their changes.

The positive requires natural replay structural/security passage, then explicit
Unsupported, and checks observation equality only to prove no verifier mutation.
Planted real DDL/grant deviations cover missing/extra/type/default/nullable
columns, an invented logical FK, CASCADE/NO ACTION drift, partial unique drift,
RLS/forced-RLS/policy/global-table violations, expanded and missing column ACLs,
PUBLIC rights, check validation and FK deferrability. Real app_user visibility
cannot turn hidden counts into admission. Real app_user cannot INSERT worker
state; actual worker constraints reject invalid/half-null conditional values.
An altered validated CHECK remains explicitly Unsupported, never accepted.

The artifact test writes `frozen62-retained-catalog-source-only.json` to pytest's
output directory with source pins, unsupported gates and a SHA256 test property.
It does not assert expression qualification. The hosted owner must retain this
artifact and replay execution evidence externally; temporary pytest paths alone
are not durable lineage. Cluster-role attribute changes and full conditional
check semantic canaries remain owed in an isolated hosted qualification lane.
No application import, pytest, SQL, type check, install, build or Docker was run
locally. Only stdlib AST/hash and the SHA-pinned Ruff formatter/linter are
permitted local validation. No local Docker daemon is used.


## v3 constraint inheritance correction

The failed hosted frozen62 oracle (39133217708) yielded an unqualified
catalog-only packet with SHA256
`57de7fdfe32d8df6952247817f4e415b54ea4cc70a681e6b2c283fb317cf9815`.
It exposed the intermediate verifier's incorrect uniform `connoinherit=false`
expectation. The fix keeps validation/deferrability checks exact and requires
true for ordinary-table primary/unique/foreign-key constraints and false for
CHECK constraints. An added genuine database canary replaces a frozen CHECK
with the same expression plus `NO INHERIT` and expects a structural refusal.
All nine existing test scenarios, their assertions, and the separate engine
fixture with explicit parameter hiding and `echo=False` are preserved.

This expectation follows frozen DDL creating ordinary tables and inheritable
CHECK constraints, together with PostgreSQL's documented inheritance semantics:
[ordinary unique/primary/foreign-key constraints are not inherited](https://www.postgresql.org/docs/16/ddl-inherit.html),
while [connoinherit identifies non-inheritable constraints](https://www.postgresql.org/docs/16/catalog-pg-constraint.html).
PostgreSQL16's authoritative implementation sets this flag in
[index_constraint_create](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/catalog/index.c)
and
[addFkConstraint](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/tablecmds.c).
The source-backed semantics, rather than the observed packet itself, determine
the fixed expectation. The packet is failed, unqualified evidence and is not
admission authority. The unconditional Unsupported gate remains unchanged.
Static inspection found the packet's column literal projection and already
checked index structural projections equal to the fixed source literals; it
did not run the module, tests, SQL or an admission decision locally.


## v4 typing repair

The general hosted CI (39133217614/job117692444734) reported type errors in
empty list inference, reused loop/spec variables with incompatible tuple
shapes, and a nullable FK lookup that the custom assertion helper did not
narrow. V4 explicitly annotates the ACL/constraint lists, separates meaningful
key/FK/index variable names, and uses an explicit None guard raising the same
RetainedSchemaRefused message. No type ignores, catalog bypasses, policy changes
or runtime guard relaxation are introduced. The v3 kind-specific inheritance
fix and unconditional Unsupported gate are preserved, as are all v3 test bytes.
Local validation is AST/source inspection and pinned Ruff only; mypy and tests
remain hosted-only. The reported first-new-test failure is not diagnosed by
this typing repair and no additional fixture/schema qualification is claimed.
