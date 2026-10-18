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
collations or operators to pretend two SQL expressions are equivalent. V6 adds
candidate exact PostgreSQL16 non-pretty `pg_get_expr(..., false)` literals for
all four CHECK constraints and three partial predicates. Every column default,
including absence, remains an exact frozen-source `_COLUMNS` literal. Column
collations and every btree index key's default opclass/collation are checked by
resolved catalog namespace/name, with no Genesis OID pins. These source-owned
rendering candidates still need the next hosted context-bearing positive and
planted-negative run; complete catalog/security qualification is still owed.
The final Unsupported gate remains unconditional.

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
`tests.test_kernel_identity_entry._seed_populated_legacy` / `entry_transaction`. The three
source files and dedicated CI database setup can be overlaid onto actual a5 for
focused qualification without future Kernel/Learning API imports. The retained
fixture requires an EMPTY `RETAINED_SCHEMA_DATABASE_URL`, asserts hosted CI and pre-existing real roles, sets
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
An altered validated CHECK is refused before the final Unsupported gate.

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


## v5 isolated retained replay fixture

General hosted CI39134155045/job117695149451 reached1092 passing tests, but the
original Kernel-entry fixture then correctly refused a nonempty entry database.
Importing its module-scoped `legacy_engine` into this separate test module had
registered another module-scoped fixture instance using the same persistent
replay database. V5 removes that dependency entirely. No original Kernel test,
fixture, migration source or database setup is changed.

The retained fixture requires declarative `RETAINED_SCHEMA_DATABASE_URL` and
hosted CI. It refuses any database name shared with a supplied Kernel-entry,
application, platform, worker or migration DSN. It checks actual initial catalog
emptiness and six pre-existing real roles, verifies the frozen source, then
replays all62 original migration files as app_admin, asserting the exact head,
revision coverage and completed transaction state before using the original
synthetic seeding helper. It does not clone a schema, accept an existing populated
catalog as Genesis, alter environment variables, stamp revisions, create models,
skip checks or reset databases. Every test body remains byte/AST-equivalent;
only the module fixture and its necessary imports change. The engine retains
explicit `hide_parameters=True`, `echo=False` and guaranteed disposal.

The ordinary CI file is a new explicit overlay sourced from exact actual-a5 CI
SHA256 `d717b35092eb76ad837f7bf8f97d737559257834e08c0da9502b7f5151bf9126`.
Its only changes are a new retained DSN targeting disposable
`academy_retained_schema`, a database owned by app_admin created beside the
unchanged Kernel-entry database, and public-schema USAGE/CREATE grants on that
new database. Existing cluster-role creation still occurs once. The temporary
oracle workflow receives exactly the same three additions; all actions,
permissions, source bindings, pytest options and artifact semantics are retained.
This CI overlay changes actual-a5 workflow bytes; it is not an unchanged-baseline
claim. The production verifier remains byte-exact to v4 and always Unsupported.
All v5 replay, SQL and type/test validation remains hosted-only; local checks are
source/AST/hash and pinned Ruff only.


## v6 candidate rendered semantics, with explicit context

This bounded slice pins the four CHECK renderings and three partial predicates
from genuine frozen DDL, PostgreSQL16 semantics and the independently source-bound
frozen62 Genesis oracle39134154982. That packet SHA256 is
`55935d64f96f2d7cffce2f96b805c35f4504dfaef62fc0416e3062e22c60411c`,
with source checkout `baf727f2e8a542db8865809e1d03a4790a64881d` and30 hosted
passing tests. It is source evidence without admission authority, not a target
or adopted-schema baseline. Its original packet has no rendering-context
metadata, so this slice does not infer its exact server minor, encoding or locale.

The source enum CHECKs use `IN`, which PostgreSQL decompiles as typed `ANY` with
ordered varchar constants coerced through text arrays. The conditional CHECK
retains every explicit IS NOT NULL guard, branch order, comparison cast and
parenthesis. Applicants' null/non-null predicates and lab_operations' queued/
claimed predicate are exact literal pins. The 166 column/type/nullability/
default tuples already fixed from source exactly matched the independent
Genesis projection, including literal, JSONB, integer, boolean, now(),
CURRENT_DATE and absent defaults; they are not replaced from observed data.

Frozen DDL declares default btree opclasses: uuid→pg_catalog.uuid_ops,
timestamptz→pg_catalog.timestamptz_ops, varchar/text→pg_catalog.text_ops.
All current indexed source types are covered. Actual operator class identities
are joined through pg_opclass/pg_namespace. Index collations now resolve each
actual indcollation identity through pg_collation/pg_namespace: collatable text/
varchar source columns require pg_catalog.default; other source types require
no collation. This also checks all column collation identities. It does not pin
Genesis numeric OIDs or approve the database default's underlying locale,
library/version, operator implementation, dependencies or full security profile.

The new catalog-only rendering_context contains only six allowlisted values:
server_version_num, server_version, search_path, effective current_schemas(true),
quote_all_identifiers and standard_conforming_strings. No arbitrary settings,
role configuration values or connection strings are captured. The source-owned
**candidate** deparser profile is PostgreSQL major16, literal default search_path
`"$user", public`, effective schemas exactly pg_catalog/public, quote-all off and
standard strings on. Non-pretty output is explicit in all expression queries.
Unknown profiles, including missing context, raise Unsupported. The prior
search-path guard remains exact and now identifies a mismatch as Unsupported.
This profile is a rendering assumption requiring hosted validation, not
permission to deploy a cluster or an assertion of complete security. Even a
matching profile ALWAYS reaches the final Unsupported gate after all fixed
checks. No new private issuer, adoption consumer, DDL or activation is added.

The old ten test scenarios remain, with only the wrong validated CHECK scenario
strengthened from Unsupported to exact structural Refused. Added real database
canaries cover broader enum values, missing conditional NULL guards, widened lab
partial uniqueness, changed and absent defaults, a pattern opclass, changed
index/column collations and unsupported deparser GUC/search-path contexts.
The independent v5 fixture, ordinary CI and temporary oracle workflow bytes are
preserved. Tests and rendering-context qualification are AUTHORED, NOT RUN in
this capsule. Local verification is stdlib AST/hash/source comparison and pinned
Ruff only; no application import, SQL, mypy, pytest or database operation ran.

Official primary references are PostgreSQL16's
[expression decompilation/current_schemas](https://www.postgresql.org/docs/16/functions-info.html),
[operator classes](https://www.postgresql.org/docs/16/indexes-opclass.html),
[builtin operator-class declarations](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/include/catalog/pg_opclass.dat),
[collations](https://www.postgresql.org/docs/16/collation.html), and
[deparser compatibility settings](https://www.postgresql.org/docs/16/runtime-config-compatible.html).
The independently reviewed planner pointer has SHA256
`752bbdc7ac2f1a5b5e45a3a9be4f05dd591c98e169f94c5b7bb686092a36fc0d`.
This doc also incorporates only the coordinator's mechanical v5b fixture-DSN
correction from doc SHA256
`ac611493aefb445413cff7255979c76d5fe0a85d4f933de5e68c16cedb9127d0`;
its own v6 rendering additions do not overwrite that correction.
