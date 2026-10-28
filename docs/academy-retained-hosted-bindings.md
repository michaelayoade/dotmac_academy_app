# Disposable hosted environment binding harness

The CI workflow declares non-secret expectations before the hosted frozen62
fixtures create and observe disposable resources. Source wiring and local
contract checks do not establish hosted execution or qualify adoption.
Production admission and whole-assembly adoption remain separate gates.

`.github/workflows/ci.yml` selects its PostgreSQL service using the repository
Variable `ACADEMY_RETAINED_PG_IMAGE`. The first step refuses an empty, mutable or
malformed image reference and compares the service container's image
configuration ID with the ID resolved from that exact declared digest. Only
`docker inspect --format '{{.Image}}'` and
`docker image inspect --format '{{.Id}}'` are used for this comparison; neither
full inspection output nor container environment is collected or printed.

The three repository Variables must describe the same immutable PostgreSQL 16
image, with facts established independently before the run:

- `ACADEMY_RETAINED_PG_IMAGE`: `name@sha256:<64 lowercase hex>`;
- `ACADEMY_RETAINED_PG_SERVER_VERSION_NUM`: numeric PostgreSQL 16 version;
- `ACADEMY_RETAINED_PG_COLLATION_VERSION`: the image's libc collation version.

The first-step image guard and binding declaration protocol both require the
untagged `name@sha256:...` form above.
The registry manifest digest selects the image. Docker's image configuration ID
is used only to check equality with the running service, and is not substituted
for the declared registry digest.

CI explicitly supplies distinct target database names for environment, history
and assembly, along with setup session, platform, encoding, locale provider,
locale names, null ICU locale, collation versions and extension versions through
`ACADEMY_RETAINED_EXPECTED_*` entries. These are disposable resource protocol
declarations. Missing or contradictory declarations fail closed.

After database setup and before pytest, Poetry runs
`scripts/declare_retained_hosted_bindings.py`. This stdlib-only helper performs
no SQL, Docker calls, DSN inspection or observed-catalog fallback. It requires
`CI=true`, `GITHUB_ACTIONS=true` and an existing, absolute, non-symlink
`GITHUB_ENV` file. It validates the bounded declaration protocol and appends
ASCII JSON values under four fixed names:

- `ACADEMY_RETAINED_ENVIRONMENT_BINDINGS`;
- `ACADEMY_RETAINED_HISTORY_BINDINGS`;
- `ACADEMY_RETAINED_ASSEMBLY_BINDINGS`;
- `ACADEMY_HOSTED_GENESIS_DECLARATION`.

Purpose bindings use `academy_retained_environment_` field prefixes. The final
value combines the immutable image, platform and three purpose declarations.
No expectation is learned from the target database or the running service.

`tests/fixtures/hosted_genesis.py` cross-checks these independent projections,
then uses `retained_hosted_genesis.disposable_genesis` to create a separately
owned container for each purpose with `--pull=never` and the declared platform.
The fixture genuinely replays all 62 frozen migrations before binding the
coordinator-owned rollback root. It neither shares the application test database
nor opens application admission. The factory checks the declared image/platform
and controlled resource identity; SQL profile equality alone does not establish
custody. Unbound public environment observation remains unsupported.

The CI job also provisions dedicated environment/history databases alongside
its application, Kernel-entry, retained-schema, ordinary-graph and fresh-token
catalogs. This provisioning is distinct from the genesis factory's purpose-owned
containers. Hosted canaries require hosted CI and their declarations; they are
not local Docker tests. JUnit execution evidence is retained by the workflow.
A successful local workflow contract test proves only the source configuration,
not a successful hosted replay, catalog qualification or adoption.

## Empty composed CI entry

The workflow checks out the exact pull-request head and declares
`ACADEMY_CI_SOURCE_REVISION` separately from GitHub's synthetic merge-run SHA.
The application database is owned by `app_admin` and carries a non-secret
database comment bound to that source revision, run ID and attempt. The CI
wrapper verifies the checkout, loopback endpoint, fixed database name, database
owner/comment, and actual login/effective roles before invoking the owner.
Neither a CLI flag nor a DSN query parameter can select another target.

Before application bootstrap, the single explicit convergence canary runs
historical adoption and fresh installation in separate rolled-back roots. It
reports H/F schema fingerprints and names of differing catalog objects. This
discovery is unqualified and cannot commit. Its equality result must be reviewed
and pinned in a separate source commit; an absent pin refuses strict bootstrap
before DDL. A discovery-only workflow cannot qualify D1.

After qualification, `python -m scripts.ci_bootstrap_composed_db
--expect-database academy` creates and commits the empty composed database.
The normal migration CLI must then be a no-op; `--verify-only` checks the
committed result in a read-only transaction. The full pytest session repeats
that sanity check. Only the exact pre-bootstrap discovery test selection is
exempt, and missing required database fixtures fail under CI. JUnit skips must
equal the separately reviewed exact allowlist (initially empty).

`academy_fresh_entry` holds rolled-back fresh/refusal cases;
`academy_facilitator_runtime` holds a separately qualified committed schema for
genuine runtime logins and concurrent capability tests; and
`academy_legacy_roundtrip` replays the exact frozen62 history for destructive
legacy roundtrip tests. They are distinct from the application database and
from the no-commit hosted genesis containers. New assembly revisions a007-a010
carry access, heartbeat, bank-version and canonical facilitator semantics.
Populated production adoption, admission and deployment remain gated.
