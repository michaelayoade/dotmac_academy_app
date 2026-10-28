# Disposable hosted environment binding harness

This source-only CI harness supplies required, non-secret expectations before
the genuine frozen62 environment fixture observes its dedicated database. It is
AUTHORED, NOT RUN. The separately reviewed environment module and canaries must
be integrated by the coordinator; this capsule contains only their CI wiring.
Public observation still always ends Unsupported, including a matching profile.
Nothing here authorizes a004, production, admission, or whole-assembly adoption.

Both workflows provision `academy_retained_environment`, owned by `app_admin`,
with the reviewed UTF8/libc/en_US.utf8 protocol and public-schema USAGE/CREATE for
`app_admin`. Existing application, Kernel-entry and retained-schema databases
and the once-created cluster roles keep their existing setup. The profile
fixture owns a separate empty database and genuinely replays all 62 frozen
migrations. It does not share another module's module-scoped engine fixture.

CI explicitly declares target database, setup session, encoding, locale provider,
both locale names and the plpgsql extension version through
`ACADEMY_RETAINED_EXPECTED_*` environment entries. These are disposable test
resource and security protocol declarations, not business policy defaults. The
helper has no missing-declaration defaults, SQL queries or observed-catalog
fallback. Declarations must match the bounded reviewed protocol; other contexts
fail with a generic Unsupported message.

After database setup and before pytest, Poetry runs the stdlib-only
`scripts/declare_retained_hosted_bindings.py`. It requires `CI=true`,
`GITHUB_ACTIONS=true`, a Linux GitHub-hosted runner, bounded job/run identifiers,
and a full service container ID supplied directly by `job.services.db.id` in
step environment. It invokes Docker using argv without a shell, collecting only:

- `docker inspect --format '{{.Image}}'` for the controlled container's image ID;
- `docker exec <id> postgres --version` for a PostgreSQL 16 release binary;
- `docker exec <id> getconf GNU_LIBC_VERSION` for the GNU libc version;
- `docker exec <id> printenv LANG` for the single allowlisted locale variable.

It never inspects full container configuration or environment, reads connection
strings, prints command output, or emits raw subprocess errors. It appends one
bounded ASCII JSON value to `GITHUB_ENV` under the fixed
`ACADEMY_RETAINED_ENVIRONMENT_BINDINGS` name. JSON keys use the required
`academy_retained_environment_` prefix. The extension list is converted to tuples
by the reviewed fixture. The libc protocol explicitly supplies null ICU locale,
and uses the trusted OS version for both expected stored and actual collation
versions. PG>=10 binary versions are encoded as major*10000+minor.

The image field is a public `sha256:<64 hex>` image configuration ID returned by
Docker, not an authenticated registry manifest digest. SQL cannot authenticate
it. Exclusive custody of the source-controlled GitHub service is an assumption
of this disposable rehearsal; these checks do not establish custody or issue an
admission proof. A mutable `postgres:16` tag remains the existing workflow image
selection. The helper refuses incompatible versions, libc or LANG without
deriving a new expected profile from the database.

Primary-source facts reviewed on 2026-10-18:

- The [official image tag library](https://github.com/docker-library/official-images/blob/master/library/postgres)
  maps the unqualified 16 tag to `16/trixie` at commit
  `9d15534160ade17f2b6c455a39ee967c49b1937d`. That
  [Dockerfile](https://github.com/docker-library/postgres/blob/9d15534160ade17f2b6c455a39ee967c49b1937d/16/trixie/Dockerfile#L47-L59)
  generates the locale and explicitly declares `LANG en_US.utf8`.
- PostgreSQL 16's
  [locale implementation](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/utils/adt/pg_locale.c#L1583-L1590)
  uses `gnu_get_libc_version()` for non-C/POSIX libc locales. Thus this locale's
  expected collation version comes from the controlled service OS, not SQL.
- The [plpgsql control file](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/pl/plpgsql/src/plpgsql.control)
  declares version 1.0 and pg_catalog schema. CI uses the freshly initialized
  official image's template database; no extension version is queried to create
  an expectation.
- PostgreSQL's [preset option documentation](https://www.postgresql.org/docs/16/runtime-config-preset.html)
  defines the numeric server version representation.

The oracle focus runs both retained-schema and environment canary suites without
adding fail-fast behavior. Their outcomes share its existing JUnit artifact.
The unchanged producer catalog collector exports only the retained-schema source
database projection. Environment projection export and its separate producer
collector review are pending. Hosted execution after independent review, full
suite coexistence, genuine environment/catalog qualification, installed
whole-assembly qualification, and adoption remain open gates.
