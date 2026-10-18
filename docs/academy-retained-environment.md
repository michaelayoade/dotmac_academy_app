# Disposable hosted Genesis environment candidate

`academy-hosted-frozen62-pg16/v1` is a source-only candidate for the disposable
GitHub PostgreSQL16 Genesis service. It is unqualified and never authorizes
production. `observe_retained_environment` always raises Unsupported after
matching fixed checks. It issues no proof or receipt, consumes no proof, grants
no a004 authority, acquires no locks, establishes no fence and manages no root.
There are no CI or Settings changes in this slice.

## Expectations and authority

The immutable internal profile fixes security protocol, source identities, six
roles and ACL semantics. There is no caller profile selector, ACL override,
namespace override or `fenced=True` argument. These historical invariants are
separate from configurable application business policy; no business defaults
are introduced here.

`HostedEnvironmentBindings` is a typed, freely constructible collection of
non-secret expectations. Construction and a matching observation prove nothing.
Trusted Settings/CI must explicitly declare every
`academy_retained_environment_<field>` before observation. Required fields are
`target_database`, `setup_session`, `service_image`, `server_version_num`,
`encoding`, `locale_provider`, `lc_collate`, `lc_ctype`, `icu_locale`,
`collation_version`, `actual_collation_version` and `extension_versions`.
Provider-specific None values must be declared, never inferred. Only the
source-permitted template extension `plpgsql` can be named, with its explicitly
declared version. No connection URL or credential belongs in these fields.
Missing fields yield Unsupported; malformed or contradictory expectations and
observations yield Refused. The adapter reads only these named fields and never
dumps Settings. Dataclass repr omits binding values.

The physical CI setup identity is `postgres`; its effective DDL identity must be
`app_admin`. Matching these SQL identities cannot authenticate the service image,
the GitHub service boundary or exclusive ownership. Their declaration is an
expectation, not attestation. Source-controlled trusted binding adoption and a
hosted genuine frozen62 projection are still required in a later slice.

## Source-derived fixed checks

All six roles LOGIN. `app_admin` INHERIT/BYPASSRLS; `academy_lab_worker`
NOINHERIT/BYPASSRLS; `app_user`, `platform_api`, `outbox_dispatcher` and
`platform_outbox_dispatcher` INHERIT/NOBYPASSRLS. All are NOSUPERUSER,
NOCREATEDB, NOCREATEROLE, NOREPLICATION, unrestricted connection-limit and
without expiry or role configuration. No explicit membership involving any of
the six is allowed, including PG16 ADMIN/INHERIT/SET options.

`app_admin` owns the target database; `pg_database_owner` owns public. Database
ACL normalization uses owner defaults when the ACL is NULL, with PUBLIC
CONNECT/TEMPORARY and no CREATE. Public schema has PUBLIC USAGE, owner and
explicit app_admin CREATE/USAGE, and frozen initial app_user/platform_api USAGE.
Grantors normalize to the source-derived owner, never an observed expectation.
Effective database/schema rights are checked separately for all six roles.
Runtime roles own no database, schema or relation, including sequences. Both
outbox roles have zero table and column rights on every retained table.

Applicable database/role settings, parameter ACL grants and default ACL
overrides are absent. The disposable candidate conservatively rejects every
default ACL override in the database, including global and schema-specific
entries. Metadata exposes configuration presence only, never raw roleconfig,
routine configuration, passwords or arbitrary settings. Safe GUC observation is
limited to replication origin, row security on, read committed writable root
and the existing fixed deparser context. The observer never changes a setting.
No preload-hook settings or raw parameter dumps are requested.

The only extension is explicitly version-bound template plpgsql, owned by
postgres in pg_catalog with no extension configuration. There are no additional
non-system routines beyond the exact frozen public `app_current_tenant_id()`.
The existing V7 checker verifies its body, signature, ACL and configuration
absence; this module does not duplicate the function body. Existing retained
structure/security checks also run. All SQL in the new module is SELECT-only,
qualified metadata; no DDL/DML, row reads, arbitrary namespace input or mutation.

## Provenance and known gaps

Base: exact retained V7 manifest
`/private/tmp/academy-retained-schema-v7-source-manifest-20261018.json`, SHA256
`7c39bfd4193c5667664e83e09b27611c8c9f51ee63a1f77784ba9f51109f635f`.
All 211 base files and modes are preserved, including the assigned CI bytes.
Only retained_environment.py, this document and its new hosted test are added.

Actual a5 CI byte-exact capture:
`/private/tmp/academy-actual-a5-ci-byte-exact-20261018.yml`, SHA256
`c786e61f4560ca874683c4fcd154ba45620b3bccef96e25a8d54960d3bd7c6e0`, Git
blob `3dfc1b9a87a97037276977e669be3336774ba020`. Role-script authority is Git
blob `d5bbe2812eb419a14287cba70d72a3bc08a20799`; only whitelisted attributes
are relevant, never its credential material. Worker ADR blob is
`c5ece5c2a11d1b176738a0ed69d44e7160dd326e`; platform ADR0002 blob is
`fb300e76b18598c24bce2bfa0a8e8298918ac4bb`.

The genuine full62 fixture inventory is checked against V7's fixed frozen hash
inventory by source AST, with a scan of all 62 migration files for extension,
role, database, schema and default-privilege authority changes. Initial frozen
schema USAGE grants and the role provisioning/CI owner setup define the ACL
expectations. PostgreSQL16 source semantics define implicit owner privileges
and ACL grantor identity; they are not a substitute for a hosted observation.

The V6 Genesis metadata SHA256
`e8558b7da245742616f779d787077e183862243a81901f978f662d694a6f55b4`
contains PG16.15 context and admission false, but has no database/schema ACL,
locale or environment profile checks. It does not qualify this profile.
Root subsequently supplied V7 hosted metadata at
`/private/tmp/academy-retained-oracle39135966658-20261018/catalog.json`,
238312 bytes, SHA256
`f8a945af9d831d007c98aa1af7c40317746dd4f0265a8f622f6f7e4c18ec0b48`
(hash/size verified locally). Root reports 58 hosted retained tests passed and
all five actual-head checks succeeded, including helper/policy observations.
This does not contain the new database/schema/default-ACL environment projection.
This new profile and its tests remain unqualified; service-image identity,
exclusive disposable boundary, trusted binding adoption and full environment
qualification remain outstanding. Existing V7 verification stays Unsupported
in its unchanged source; this slice does not close or override its gates. Kernel106 is already released; no old local
Kernel105 state or Kernel API is used as profile authority.

New tests own an independent genuine frozen62 replay through `profile_engine`,
requiring NEW `RETAINED_ENVIRONMENT_DATABASE_URL` distinct from the retained,
entry and general databases. Importing the existing module-scoped retained_engine
would re-register its fixture and initialize the same database twice during full
collection; this slice deliberately avoids that ownership bug. Next root-owned
CI wiring must provision the dedicated profile database and binding declaration.
There is no populated fallback, skip or environment mutation, and no full-suite
collection-readiness claim. Tests use explicit prior CI expectations and
rollback-only planted role, membership, ACL, ownership,
settings, GUC, extension, routine and environment mismatch cases. They check
SELECT-only behavior and unchanged metadata/root on Unsupported. They contain
no create_all, stamps, skips or fabricated catalog positive. Tests are AUTHORED,
NOT RUN; runtime/import/type/SQL/build/install execution is hosted-only.
Local validation is restricted to stdlib source AST/hash/TOML and pinned Ruff.

PostgreSQL16 primary semantics:

- [Privileges and defaults](https://www.postgresql.org/docs/16/ddl-priv.html)
- [GRANT ownership and grantors](https://www.postgresql.org/docs/16/sql-grant.html)
- [pg_database_owner implicit membership](https://www.postgresql.org/docs/16/predefined-roles.html)
- [PG16 membership options](https://www.postgresql.org/docs/16/catalog-pg-auth-members.html)
- [Database locale catalog](https://www.postgresql.org/docs/16/catalog-pg-database.html)


## V2 initial hosted metadata capture

V2 adds an explicit None guard before any observation in the public observer,
preserving the missing-binding exception class and message while allowing static
nonoptional type narrowing. It changes no remaining profile validation. V1 is
immutable; all 211 original base files and modes remain exact.

The LAST test,
`test_capture_unqualified_frozen62_environment_metadata`, depends on the genuine
`profile_engine` and pytest `tmp_path`/`record_property` only. It does not request
`hosted_bindings`, derive expectations, call fixed-profile checks or claim PASS.
The test privately reads the 17 fixed metadata queries and writes:

`frozen62-retained-environment-source-only.json`

The JUnit properties are `retained_environment_metadata_path` and
`retained_environment_metadata_sha256` (SHA256 of exact UTF-8 JSON bytes with
trailing newline). A separate root-owned CI harness can collect this matching
basename. No workflow or existing fixture is changed here.

The JSON object has `kind: unqualified_frozen62_hosted_environment`,
`schema_version: 1`, `admission_authority: false`, `source_only: true`, fixed
source identity in `source_profile`, `fixed_profile_checks: NOT RUN`,
`binding_expectations: NOT SUPPLIED`, `catalog` and `unsupported_gates`. Catalog
keys exactly match the observer's fixed 17-key metadata allowlist; rows are JSON
arrays preserving query column order. Explicit unsupported reasons include
trusted binding adoption, fixed-check/canary qualification, service-image
authentication and exclusive-boundary authentication. Source identity identifies
the candidate and does not attest the running service.

Serialization accepts only exact strings, integers, booleans, None and nested
tuples. It does not stringify unknown objects, serialize caller bindings, read
rows, expose credentials/DSNs/passwords or output raw role/routine configuration.
Role configuration and routine-authority checks expose presence booleans only.
This artifact is always UNQUALIFIED and has no admission, proof, fence, consumer
or production authority. No runtime, import, test, type or SQL execution was
performed locally. Existing seven test-function and fixture ASTs are preserved;
the new capture is authored, not run.
