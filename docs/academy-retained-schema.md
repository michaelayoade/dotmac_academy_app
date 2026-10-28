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

The ordinary CI overlay was built from the captured CI template SHA256
`d717b35092eb76ad837f7bf8f97d737559257834e08c0da9502b7f5151bf9126`.
The coordinator subsequently verified that template had one extra final newline;
it was not byte-exact actual-a5 CI. This capsule preserves the assigned v6 CI
bytes, including that serialization artifact. The intended changes are a new retained DSN targeting disposable
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

## v7 candidate tenant-helper and policy-dependency contract

V7 adds only the public tenant helper and its ten policy dependency closures.
The source is the genuine initial migration's `_create_current_tenant_function`
at line373 and `_grant_roles` at line414. Its exact dollar-quoted prosrc body,
including the leading/trailing whitespace, independently hashes to SHA256
`ca9e519dc5f4b681d52f888372ae6bb867cf622cd38fdc38cd471a1fa430bb12`.
The passed Genesis MD5 `d75e12d0c59d482c4c709162aafb5df2` corroborates that
body, but is no longer the observation's only source fingerprint. The observer
fetches this named helper family only and hashes its exact UTF-8 body in Python,
without a PostgreSQL extension. The verifier checks both exact body equality and
SHA256. No SQL/body whitespace normalization or copied live expected value is
used. The packet's helper body is schema source code, not application row data.

The observer now records every public same-name routine. The fixed contract
requires exactly one normal no-argument function, with no overloads, returning
pg_catalog.uuid, owned by app_admin and implemented in plpgsql. It requires
STABLE, SECURITY INVOKER, non-leakproof, parallel unsafe, nonstrict, non-set
return, no argument/default/variadic/support/transform/config/binary/SQL-body
overrides, default plpgsql cost100 and non-set rows0. Input/all-argument types
resolve through actual pg_type/pg_namespace identities. Language and helper
OIDs are observations, never literal Genesis OID pins. Configuration and other
required-absent override fields are observed as absence booleans, so arbitrary
configuration values or default expressions are not retrieved or dumped.

Helper ACLs are fixed from the explicit app_user/platform_api EXECUTE grant and
PostgreSQL's built-in owner/PUBLIC EXECUTE defaults. All four entries require
app_admin as grantor and no explicit grant option. PUBLIC EXECUTE is preserved,
not prohibited; the owner's implicit grant options are not ACL stars. The
observer reads actual effective EXECUTE for every actual pg_roles row. Every
role must have execution under the source PUBLIC grant, including the worker,
which receives no invented helper-specific grant. No inheritance claim is used
to substitute for that real privilege check. This does not qualify ambient
cluster roles, their reachable schemas or ownership/SET ROLE authority.

Policy dependency classes resolve to catalog namespace/name. Each of the ten
policies must have exactly five pg_depend rows: one automatic dependency on its
actual owning table, two normal dependencies on its actual tenant_id column,
and two normal dependencies on the actual checked helper. PostgreSQL16 records
USING and WITH CHECK separately, producing the duplicate normal edges. The
verifier compares sorted tuples, preserving multiplicity rather than converting
to a set. The observer also captures every matching current-database pg_shdepend
row; the frozen PUBLIC policies require no shared role dependency, exactly as
PG16 policy.c skips PUBLIC. A real TO app_user policy canary verifies refusal of
the newly recorded shared role edge. Actual table OIDs and tenant attribute numbers come from independently
checked table/column observations; the helper OID is derived inside the closure
check from the source-qualified actual helper. There is no caller-supplied OID,
namespace, expected value or dependency override. Unknown referenced catalog
classes remain in the observation via LEFT JOIN and fail the exact comparison.

All thirteen v6 test functions/scenarios, their assertions, the candidate
rendering checks, isolated v5 fixture, ordinary CI/workflows and coordinator's
v5b doc fix are preserved. Added hosted canaries cover body replacement,
extra signature, SECURITY DEFINER, strictness, volatility, parallel safety,
function-local configuration, cost, missing/extra/default-PUBLIC grants and
grant options. A natural real-role canary exercises app_user/worker helper
execution and valid/invalid tenant settings. A policy WITH CHECK(true) canary
retains the same unique endpoint set while removing one copy of the normal
edges. A shadow-schema replacement canary creates a source-identical new public
helper while actual policies still refer to the old helper OID; isolated helper
checks pass but dependency closure refuses. No fake catalogs are positives.
These new canaries are AUTHORED, NOT RUN locally.

The coordinator reported the v6 frozen Genesis oracle39135138894 passed42
hosted cases on source checkout `8c9dee50870b1fbc163c05af1ad791d0f8559cdc`.
Its catalog SHA256 is
`e8558b7da245742616f779d787077e183862243a81901f978f662d694a6f55b4`;
its observed narrow context was PostgreSQL160015, standard/default deparser
settings and effective pg_catalog/public schemas. That validates only this
source-bound rendering observation, not all PG16 minors, the new v7 attributes/
ACL projection, a deployed security profile or adoption. V7 still ends at the
same unconditional Unsupported verifier, and issues no proof/receipt or DDL.

Remaining gates include hosted v7 helper/ACL/dependency qualification; full
constraint/operator/type/index and incoming/outgoing RI-trigger/dependency
semantics; a separately reviewed environment SecuritySpec; complete physical
Connection/root/XID/OID/cohort continuity under the actual fence/ordered locks;
private phase proof and a004; whole-product/ERP/Integration conservation and
recovery. No compensating repair, migration runner, issuer or consumer is added.

Official primary sources are PostgreSQL16's
[pg_proc fields](https://www.postgresql.org/docs/16/catalog-pg-proc.html),
[CREATE FUNCTION defaults](https://www.postgresql.org/docs/16/sql-createfunction.html),
[function default implementation](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/functioncmds.c),
[privileges and PUBLIC defaults](https://www.postgresql.org/docs/16/ddl-priv.html),
[dependency meanings](https://www.postgresql.org/docs/16/catalog-pg-depend.html),
[shared dependencies](https://www.postgresql.org/docs/16/catalog-pg-shdepend.html), and
[separate policy dependency recording](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/policy.c).


The coordinator's CI byte-provenance correction is recorded separately at
receipt SHA256 `0d31c181f52e8b1c91168e989edb02435eb6e9c0fb577b89f3b718faa35a64db`.
Actual-a5 CI is5719 bytes, blob `3dfc1b9a87a97037276977e669be3336774ba020`,
SHA256 `c786e61f4560ca874683c4fcd154ba45620b3bccef96e25a8d54960d3bd7c6e0`.
V7 retains its assigned v6 CI6083 bytes exactly, rather than silently changing
an unowned file. The coordinator's separate6082-byte candidate correction
SHA256 `21f79b71dbc65021a6947bcfa296b8d79465e1fd872442249d6988c4228b91a9`
removes only the unintended final newline and is reserved for the next owned
composition. Earlier immutable source/proof records compared against the
captured template, not byte-exact actual-a5 CI; no unchanged-actual-CI or exact
five-lines-only-against-actual-a5 claim is made here. The extra newline has no
execution effect and does not qualify or invalidate schema admission.


## V8 candidate touching FK and RI closure

This slice checks the initial historical public graph only. Frozen62 declares
17 outgoing FKs touching the eleven retained tables. Its only incoming retained
edges are onboarding_tasks→applicants and lab_operations→lab_instances, already
included in those seventeen. Full62 source inventory finds no other retained
incoming references. Additional incoming FKs fail even when their child is
outside the retained set. No logical UUID relationships become invented FKs.

Six fixed supporting parent keys are tenants_pkey; uq_people_tenant_id_id;
uq_applicants_tenant_id_id; uq_lab_instances_tenant_id_id;
uq_cohort_tracks_cohort_track; and uq_question_banks_tenant_id_id. Parent
relations, columns, physical positions, UUID types, constraint/index names and
actual OID associations are checked independently of the adopted catalog.
UUID FK equality resolves actual pg_catalog.=(uuid,uuid) and uuid_eq identities;
no literal Genesis OIDs are expected. The parent supporting indexes are checked
for their source uniqueness, validity, immediate enforcement, BTREE uuid_ops,
column order, absence of expressions/predicates/collations and source key
constraints. Source UUID columns have no server defaults.

PostgreSQL 16 tablecmds.c and trigger.c generate four internal RI triggers per
FK: child AFTER ROW INSERT (5)/UPDATE (17), parent DELETE (9)/UPDATE (17).
The source CASCADE deletions use RI_FKey_cascade_del; the two applicant Learning
references use RI_FKey_noaction_del. Every update uses NO ACTION. All 68 triggers
must be enabled for origin, internal, nondeferrable, initially immediate,
without arguments, column filters, qualifications, transitions or parent-trigger
overrides. Their actual constraint, opposite relation and supporting index OIDs
must match the fixed graph. Internal trigger names use PostgreSQL's prefix plus
the actual trigger OID. Disabled, replica-only, always-enabled, custom internal
or unassociated triggers fail.

The exact candidate pg_depend multiset comprises 67 FK column/index edges,
68 trigger→FK internal edges, twelve supporting-key→column auto edges, and six
supporting-index→key internal edges: 153 rows. Builtin UUID operators/opclasses
and RI functions are PostgreSQL pinned objects, whose dependency edges are
omitted by pg_depend.c. Multiplicity is preserved; extra incoming dependencies
to the touching FKs or selected RI triggers fail. This expected set comes from
frozen DDL and PostgreSQL source, never from copying a live adoption packet.

External parents tenants, people, cohort_tracks and question_banks also carry
legitimate unrelated frozen FK-owned internal triggers. This slice observes
and classifies those only as external-parent FK-owned associations. Their
functions, firing modes, full FK families and dependency closure require their
actual owner's composed catalog qualification. External-parent noninternal or
unassociated internal extras fail. This is a seventeen-FK closure, not a claim
that every unrelated owner's graph has been qualified.

All new RI projections and 153-row expectations are source candidates pending
genuine hosted frozen62 replay. The existing eighteen test functions, isolated
replay fixture, rendering/helper/context guards, CI bytes (including the
previously disclosed extra final newline) and unconditional final Unsupported
remain unchanged. New authored PostgreSQL canaries mutate only the disposable
hosted transaction; system-trigger/catalog negatives require its actual
superuser and restore app_admin before observation. No new tests ran locally.
Remaining gates include hosted RI qualification, unrelated owner graph closure,
reviewed environment SecuritySpec, private fence/ordered locks and physical
transaction continuity, genuine identity relocation, a004, and whole-product
conservation/recovery. No admission receipt or production activation exists.

Primary semantics: [pg_trigger](https://www.postgresql.org/docs/16/catalog-pg-trigger.html),
[pg_constraint](https://www.postgresql.org/docs/16/catalog-pg-constraint.html),
[tablecmds.c](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/tablecmds.c),
[trigger.c](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/trigger.c),
[pg_constraint.c](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/catalog/pg_constraint.c),
[pg_depend.c](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/catalog/pg_depend.c),
and [index.c](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/catalog/index.c).


## V8 hosted external-trigger association correction

The failed source-bound oracle39137343027 exposed a projection/validation
mismatch, not a new expected catalog authority. The observer includes every
unrelated trigger located on the selected external parent relations. Such a
relation can itself be the child of another FK. The previous gate required
only the parent-side orientation and therefore rejected genuine check triggers
on those relations before many negative canaries reached their planted drift.

The correction retains the full projection and requires each unrelated trigger
to be internal, associated with an actual FK, and to have exactly either the
(child, parent) or (parent, child) pair of trigger relation/opposite relation
OIDs from that FK. PostgreSQL16 tablecmds.c passes those respective pairs to
CreateTrigger in CreateFKCheckTrigger and createForeignKeyActionTriggers.
Named projection fields make this endpoint distinction explicit. Neither
orientation qualifies the unrelated owner's full function/firing/dependency
contract; that composed owner gate remains owed. Custom/noninternal,
unassociated, non-FK and mismatched-endpoint triggers still refuse.

The genuine frozen62 baseline now asserts that both non-self orientations are
present. Four authored hosted canaries clear the FK association or opposite
relation for each side, retain the affected row in the observation and require
exact base Refused. Prior tests and all graph/dependency expectations are
preserved. Only source AST/hash and pinned Ruff checks ran locally. A new
hosted replay is required; no hosted pass or admission is claimed. The final
Unsupported gate remains unconditional.
