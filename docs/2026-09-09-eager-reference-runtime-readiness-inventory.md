# `dotmac_kernel.db` runtime-readiness inventory — `dotmac_academy_app`

**Status:** characterization only. No repin, no migration activation, no
adoption claim, no runtime switch. This document and its ratchet exist so the
first product-bound-runtime pilot (Kernel's forthcoming
`ProductAssemblySpec.database_runtime` / `require_database_runtime` seam) has
an exact map of what Academy reaches today, before anyone tries to cut over.

**Kernel surveyed:** `dotmac-kernel` 0.1.0a38 (Academy's exact pin,
`pyproject.toml:34`), read at tag `dotmac-kernel-v0.1.0a38` from the
`dotmac_starter_mt` history — not the current `main` of that repo, which has
moved to a10x series. All kernel citations below are against that tag.

**Method:** static reading only (AST-level `grep`/`Read`, no execution). No
package is installed in this worktree (`poetry env info -p` returns empty,
`ruff`/`mypy` are not on this machine — see "Static checks" at the end). All
claims are marked MEASURED (read directly, file:line given) or INFERRED
(reasoned from adjacent measured facts, marked explicitly).

## The one sentence that matters most

**Even if every direct `from dotmac_kernel.db import ...` in Academy's own
tree were deleted, importing `app.assembly` (hence `app.kernel_runtime`,
hence `app.main`) would still build the eager reference engine**, because
resolving `dotmac_kernel.create_app` — itself required for Academy to boot at
all — transitively imports `dotmac_kernel.db` inside the kernel's own module
graph, with no Academy code in the chain:

```
app.main (line 5: "from app.kernel_runtime import create_academy_app"; line 7 CALLS it at import time)
  → app.kernel_runtime:14  "from dotmac_kernel import create_app"
    → dotmac_kernel/__init__.py:281-290  __getattr__("create_app")
        (docstring, MEASURED: "app_factory, which imports the DB/middleware
         stack and constructs the SQLAlchemy engine at import")
      → dotmac_kernel/app_factory.py:50  "from dotmac_kernel.middleware.tenant import TenantResolverMiddleware"
        → dotmac_kernel/middleware/tenant.py:39  "from dotmac_kernel.db import resolver_session"
          → dotmac_kernel/db.py:39-40  engine = create_engine(settings.database_url, ...)
                                        platform_engine = create_engine(...)
```

This is the path a first-pass cleanup (grep Academy's own files for
`dotmac_kernel.db`, delete the hits) will not touch, because none of it is
Academy code — it is unconditional, module-scope code inside
`dotmac_kernel.app_factory` that runs the instant anything asks the kernel
package for `create_app`. `app_factory.py` installs
`TenantResolverMiddleware` unconditionally (`app.add_middleware(TenantResolverMiddleware)`,
`app_factory.py:470`, no feature flag around it), and that module's own
import (line 39) is at module scope, not deferred the way `app_factory.py`
itself carefully defers `dotmac_kernel.db` inside `_tenancy_errors()`
(`app_factory.py:106-135`, comment at line 110: "importing `dotmac_kernel.db`
builds the engine … `create_app` must stay importable without a database")
and `_required_setting_errors()` (`app_factory.py:147-179`, same rationale at
line 150). The kernel's own module docstring
(`dotmac_kernel/__init__.py:9-12`) states the DB-session/guard/middleware
surface is submodule-only "because importing them constructs the SQLAlchemy
engine from `DATABASE_URL`" — but `middleware/tenant.py`, which
`app_factory.py` imports unconditionally at its own module scope, is exactly
that submodule, imported eagerly rather than deferred like the two functions
above it in the same file.

Two more redundant, independent paths converge on the same engine even before
the kernel-side one is reached (see the reach table below): Academy's own
`app.api.deps` (request path) and `app.web.context`/`app.web.labs` (web) both
import `dotmac_kernel.db` directly. Deleting all three of Academy's own hits
would still leave the kernel-side path above. **This is the path the pilot
will trip over**: a Kernel `database_runtime` seam that lets a product bind
its own runtime instead of the eager reference one has to intercept
`app_factory`'s own middleware-install chain, not just Academy's call sites —
otherwise `create_app(assembly)` keeps building
`dotmac_kernel.db`'s two engines regardless of what Academy configures.

## Per-family reach table

| Family | Direct reaches (count) | Transitive reaches (count) | Local `create_engine`/`sessionmaker` |
|---|---|---|---|
| `create_app` / boot | 0 (Academy's own boot files never import `dotmac_kernel.db` by name) | 1 chain, reached from 2 independent entry points (`app.main`, `app.kernel_runtime`) | none |
| API dependencies (request path) | 1 file (`app/api/deps.py`), consumed by 6 router files | Same as boot (any router import pulls in `app.assembly` → the chain above) | none |
| CLI (`app/cli.py`) | 1 file, 1 import line | Same kernel-side chain is NOT triggered by the CLI (the CLI never imports `app.assembly`/`create_app` — MEASURED, see below) | none |
| Web (`app/web/*`) | 2 files (`app/web/context.py`, `app/web/labs.py`) | Same as boot, plus `app/web/labs.py` imports `TenantResolverMiddleware` directly (belt-and-braces with the kernel's own install) | none |
| Scripts / tasks / workers | 0 | 0 (MEASURED — see below) | 2 sites: `app/services/lab_jobs.py:42-43`, `scripts/seed_academy_demo.py:51-52` |

### `create_app` / application boot

Direct: none. `app/kernel_runtime.py:14` imports only the top-level
`create_app` name, `app/main.py:5,7` imports and immediately calls
`create_academy_app()`.

Transitive: the chain in "the one sentence that matters most" above. It is
reached by BOTH of Academy's two boot files, redundantly:

- `app/main.py:5` → `app/kernel_runtime.py:14` → kernel chain
- Anything importing `app.assembly` directly (e.g. a test fixture) reaches
  the SAME kernel chain via a second route: `app/assembly.py:21-56` imports
  `app.api.auth`, which imports `app.api.deps` (`app/api/deps.py:8`,
  `from dotmac_kernel.db import get_db, get_platform_db` — direct, module
  scope), and separately imports `app.web.labs`
  (`app/web/labs.py:24-25`, direct `dotmac_kernel.db.SessionLocal` +
  `dotmac_kernel.middleware.tenant.TenantResolverMiddleware`). So merely
  importing `app.assembly` reaches the eager engine THREE independent ways
  before `create_app()` is ever called: Academy's own API deps, Academy's
  own web module, and (once `create_app` itself is resolved a moment later
  in the same boot) the kernel's own `app_factory` chain.

Also present at boot, deferred-but-real (MEASURED): `app_factory.py`'s
`_tenancy_errors()` (lines 106-135) runs because Academy sets `TENANCY=single`
(`.env.example:13`, `app/config.py:86-93`) — it opens
`dotmac_kernel.db.resolver_session()` and queries `dotmac_kernel.models.Tenant`
against the live `tenants` table. This is not just an import: it is an
executed query against Academy's own migrated `tenants` table
(`alembic/versions/20260504_0001_initial_tenant_schema.py:90-111`) using a
SQLAlchemy model class Academy did not write. It currently succeeds because
the columns happen to match (see collision #1 below) — this is boot-time
behavior, not merely import-time.

### API dependencies (request path)

Direct (MEASURED): `app/api/deps.py:8`,
`from dotmac_kernel.db import get_db, get_platform_db`, used as
`Depends(get_db)` at lines 35 and 79 (`require_user_auth`, `require_role`).
Six router files depend on this module: `app/api/auth.py`,
`app/api/persons.py`, `app/api/erp_applicant_assessments.py`,
`app/api/rbac.py`, `app/api/admissions.py`, and `app/api/deps.py` itself
(`grep -rln "get_db\b" app/api` → those 5 files + `deps.py`).

This is the sharpest of the direct reaches: it is on the hot path of every
authenticated JSON request, not a boot-time or CLI-time side effect.

### CLI (`app/cli.py`)

Direct (MEASURED): `app/cli.py:27`,
`from dotmac_kernel.db import platform_session, tenant_session_by_slug`.
Also `app/cli.py:29`, `from dotmac_kernel.models import Tenant as KernelTenant`.

The CLI's own docstring at lines 39-51 (`_tenant_session`) states the
collision explicitly and is worth quoting verbatim because it is the
clearest first-party acknowledgment of collision #1 in the whole repo:

> "Yields the KERNEL's `Tenant`, not `app.models.tenant.Tenant`: the kernel
> resolves the slug against its own model. Both map the `tenants` table, and
> the CLI only reads `.id`/`.slug`, so this works — but two mapped classes
> for one table is exactly the duplication that adopting the kernel's
> `Tenant` outright would remove."

Transitive: `app/cli.py` does NOT import `app.assembly` or
`app.kernel_runtime` (MEASURED — no such import in the file; the CLI is a
standalone `argparse` entry point, `python -m app.cli`, per its own
docstring at lines 1-16). So the CLI does not reach the kernel-side
`app_factory`/`middleware.tenant` chain at all — its only reach is the
direct import above. This is a genuine, narrower reach than boot/API/web.

### Web (`app/web/*`)

Direct (MEASURED):
- `app/web/context.py:11`, `from dotmac_kernel.db import SessionLocal`, used
  at line 45 to open a bare, unscoped session inside `nav_context` — the
  Jinja context processor run for every rendered admin page
  (module docstring, lines 1-6: "runs for EVERY rendered page").
- `app/web/labs.py:24-25`, `from dotmac_kernel.db import SessionLocal` and
  `from dotmac_kernel.middleware.tenant import TenantResolverMiddleware`,
  `SessionLocal()` used at line 432.

**This is worth flagging on its own terms, independent of the runtime-seam
question.** `dotmac_kernel/db.py`'s own module docstring (lines 1-13)
narrates the exact production incident from
`docs/kernel-alignment-gap-analysis.md` — "A `dotmac_academy_app` audit
command did exactly this and reported a clean estate against a database
holding 333 banks" — as the canonical warning against calling bare
`SessionLocal()` instead of a tenant-scoped session, because RLS fails
*closed* and an unscoped session cannot be told apart from an empty tenant.
`app/web/context.py:45` and `app/web/labs.py:432` are live, present-day
instances of exactly that call shape (bare `SessionLocal()`, no
`set_tenant`/`tenant_session`), not a retired mistake. `nav_context`'s
try/except wrapper (it "must never raise") means a failure here degrades
silently to empty nav state rather than crashing — which is the same
fail-closed-and-invisible shape the kernel docstring warns about, on a
render path that runs on every page view. I have not traced whether these
two call sites are pre-existing (kept intentionally, e.g. because nav
context genuinely needs a bare session before a tenant is resolved) or a
regression against the fix `docs/kernel-alignment-gap-analysis.md` describes
as landed (#111) — this needs a decision from whoever owns that area, not
resolution here.

Transitive: same kernel-side chain as boot (`app.web.labs` is imported by
`app/assembly.py:43-44`, which is imported by `app.kernel_runtime`).

### Scripts / tasks / workers

Direct: none (MEASURED — `grep -rn "dotmac_kernel" scripts app/services` found
no hits in `scripts/` and only `app/services/exceptions.py` (compatibility
import of exception classes, not `db`) and the comment in
`app/models/entrance_defaults.py:5` in `app/services`/models, neither of
which is a scripts/tasks/workers file).

Transitive: none, as long as the script/worker does not import `app.assembly`
transitively. `app/services/lab_jobs.py` imports `app.config`,
`app.models` (package `__init__`, MEASURED to have no `dotmac_kernel` import
via the model files checked — `app/models/base.py`, `tenant.py`, `auth.py`,
`rbac.py`, `person.py` all import only SQLAlchemy and `app.models.base`),
`app.services.lab_lifecycle`, `app.services.labengine.interface` — none of
these was checked exhaustively for a further transitive `app.assembly`
import; I checked the direct dependency graph two hops deep and found none,
but I have NOT walked every file `lab_lifecycle.py` and `labengine/interface.py`
import. **This is an open gap, not a confirmed zero** — flag before treating
"scripts/tasks: 0" as settled.

## Local `create_engine`/`sessionmaker` classification

Two sites, both MEASURED, both apparently deliberate rather than legacy or
accidental — but neither carries an explicit ADR or comment saying "this is
deliberately independent of the kernel runtime," which is worth requesting:

1. `app/services/lab_jobs.py:34-49`, function `admin_session()`. Docstring:
   "Cross-tenant jobs need a role that sees every tenant's rows; the
   per-request `app_user` session is RLS-scoped to one tenant. The engine is
   created and disposed per call." Binds to
   `settings.migration_database_url` (Academy's own `app.config`, not the
   kernel's `dotmac_kernel.config`), used by cross-tenant lab
   provisioning/reaper jobs (`drain_once`, `reap_idle` — module docstring,
   lines 1-16) that must run as `app_admin` (BYPASSRLS). This looks
   deliberate: the kernel's `get_db`/`tenant_session` are single-tenant by
   design (RLS-scoped), and the kernel's own `platform_session` is a
   different role (`platform_api`, not `app_admin`) for a different purpose
   (control-plane settings, not bypassing tenant RLS across tenant tables).
   INFERRED: this may be exactly the gap the kernel does not yet have an
   equivalent for (an explicit BYPASSRLS cross-tenant session helper) —
   worth a question to whoever owns the kernel roadmap, not a finding that
   this is wrong today.

2. `scripts/seed_academy_demo.py:51-52`. Standalone demo/seed script, run
   as `python scripts/seed_academy_demo.py`, binds to the same
   `settings.migration_database_url`. No kernel import at all. This reads as
   legacy-or-deliberate-and-untouched: a one-off seeding script that predates
   (or was never migrated to) any kernel session helper. It duplicates the
   exact `create_engine`/`sessionmaker` pattern from `lab_jobs.py` rather than
   sharing it, which is a smaller, independent finding (two copies of the
   same "give me an app_admin session bound to MIGRATION_DATABASE_URL"
   pattern) — not resolved here.

Neither site imports `dotmac_kernel.db`, so neither appears in the reach
table above; they are local constructions of an entirely separate engine
against a different role/URL, not a fork of the kernel's default `app_user`
engine.

## The seven model/lineage collisions

The count of seven is CORRECT and already named and tracked — it is not my
finding, it is `tests/architecture/kernel_duplication_baseline.txt` (7
non-comment lines) and `docs/adr/0007-academy-is-a-kernel-assembly.md`'s
"Deferred work" section, which names the ratchet: "The duplication ratchet
keeps the remaining seven model collisions visible and prevents new ones."
The existing ratchet (`tests/architecture/test_kernel_duplication.py`) is a
well-built two-directional example of exactly the pattern this brief asks
for — I did not need to build a new one for model duplication, only for
`dotmac_kernel.db` reach (below).

The seven, verbatim from the baseline file (`app/models/*.py:ClassName`):

1. `app/models/auth.py:AuthSession` — same class name and same table name
   (`auth_sessions`) as `dotmac_kernel.models.AuthSession`
   (kernel `models.py:335-336`). **Columns diverge**: kernel's `AuthSession`
   has `party_id` (FK into `parties`) where Academy's has no such column
   (Academy has no `parties` table at all — MEASURED, no `create_table`
   for `parties`/`party_persons`/`party_organizations` anywhere in
   `alembic/versions/`). If any Academy code path executed the kernel's
   `AuthSession` ORM class against Academy's physical `auth_sessions` table,
   it would fail (missing column/FK target). MEASURED: no such call site
   exists today — only Academy's own `app/models/auth.py:AuthSession` is
   queried in Academy code.
2. `app/models/auth.py:UserCredential` — same story: kernel's
   `UserCredential` (`models.py:292-333`) is keyed by `party_id`, has no
   `email` column, and its FK constraint
   (`fk_user_credentials_tenant_party`) targets `parties`. Academy's
   `user_credentials` table (`alembic/versions/20260504_0001_initial_tenant_schema.py:178-`)
   has `person_id` and `email` instead. Same latent, unexercised
   incompatibility as (1).
3. `app/models/base.py:Base` — a different `DeclarativeBase`/registry
   entirely (Academy: `app/models/base.py:10`; kernel: its own `Base` in
   `dotmac_kernel/models.py`). No table-name collision (it's a Python
   metaclass, not a mapped table), but it means Academy's own migrations and
   the kernel's model definitions live in two independent SQLAlchemy
   metadata registries pointed at ONE shared Postgres schema (`public`) —
   nothing keeps them in sync if either side adds/removes/retypes a column.
4. `app/models/base.py:TimestampMixin` — same shape of collision as (3),
   name-only, no DB impact by itself.
5. `app/models/rbac.py:Role` — same table name (`roles`). Columns currently
   match (id, tenant_id, slug, name — MEASURED against
   `alembic/versions/20260504_0001_initial_tenant_schema.py:267-293` vs
   kernel `models.py:238-259`), but kernel's `Role` additionally declares
   `UniqueConstraint("tenant_id", "id", name="uq_roles_tenant_id_id")`
   (`models.py:246-249`) — I have not confirmed whether Academy's migration
   also created that composite unique. If it did not, any future kernel-side
   FK that assumes it (e.g. a composite FK the way `PartyRole` uses one
   against `parties`) would fail against Academy's physical table. Flagged,
   not confirmed either way — read the migration's full constraint list
   before relying on this.
6. `app/models/tenant.py:Tenant` — same table (`tenants`), and per my
   column-by-column read (`alembic/versions/20260504_0001_initial_tenant_schema.py:90-111`
   vs kernel `models.py:78-99`), columns currently MATCH exactly (id, slug,
   name, is_active, suspended_at, deleted_at + timestamps). This is the one
   collision that is column-identical today, which is exactly why
   `_tenancy_errors()` (see boot section above) can silently succeed
   querying the kernel's `Tenant` class against Academy's table — a working
   accident, not a designed contract, since nothing enforces the two stay in
   sync.
7. `app/models/tenant.py:TenantDomain` — same table (`tenant_domains`); not
   individually column-compared here (time-boxed) but flagged as the same
   class of risk as (6).

**Not in the tracked seven, but a real table-name collision I found that the
existing ratchet's scope does not catch**: `AuditEvent`. Academy's
`app/models/rbac.py:AuditEvent` (table `audit_events`) collides by table name
with `dotmac_kernel.audit.AuditEvent` (also `audit_events`,
`dotmac_kernel/audit.py:32-33`). The existing test
(`test_kernel_duplication.py:60-63`) only compares against
`dotmac_kernel.models.__all__`, and `AuditEvent` lives in the separate
`dotmac_kernel.audit` module, so it is invisible to that ratchet by
construction, not by oversight in Academy's favor. I am not resolving or
re-scoping that test here — it is out of this task's brief — but it should
be named as a gap in the existing ratchet's coverage, not folded silently
into "the seven."

Observed behavior, precisely:
- **At boot**: only collision (6) `Tenant` is actually exercised (via
  `_tenancy_errors()`), and only because `TENANCY=single` is set. It
  succeeds today because columns match.
- **On a request**: none of the seven collisions is exercised via the
  kernel's classes — Academy's request-path code (`app/api/deps.py`,
  routers) queries only `app.models.*` classes, never
  `dotmac_kernel.models.*`. The `get_db`/`get_platform_db` reach in "API
  dependencies" above is a session-factory reach, not a model-collision
  reach — worth keeping those two kinds of "reach" distinct.
- **Via CLI**: collision (6) `Tenant` is exercised again, explicitly and
  self-documented (`app/cli.py:39-51`, quoted above) — `tenant_session_by_slug`
  returns the KERNEL's `Tenant`, read for `.id`/`.slug` only.

## The ratchet

Written as `tests/architecture/test_eager_reference_runtime_reach.py` +
`tests/architecture/eager_reference_runtime_reach_baseline.txt`.

Per family (`boot`, `api_deps`, `cli`, `web`, `scripts_tasks`): a fixed list
of the representative files identified above, AST-parsed for direct
`dotmac_kernel.db` imports (count), plus a
`subprocess.run([sys.executable, "-c", ...])` probe that imports the
family's real entry module in a CLEAN child process and checks
`"dotmac_kernel.db" in sys.modules` afterward — a same-process check would
be contaminated, since `tests/architecture/test_kernel_assembly.py` already
imports `app.main` at module scope, so `dotmac_kernel.db` is in `sys.modules`
for the whole pytest run regardless of any one family's own behavior.

Two-directional, matching the existing model-duplication ratchet's shape:
fails if a family's count RISES above baseline (new reach) OR FALLS below
baseline without the baseline file being edited in the same change (a silent
shrink — exactly the "looks retired, isn't" failure mode this task exists to
prevent, since a Kernel seam landing elsewhere does not by itself mean
Academy stopped executing the eager runtime).

Direct-import counts were hand-verified against the actual files with a
standalone AST walk before being pinned (`boot`=0, `api_deps`=1, `cli`=1,
`web`=2, `scripts_tasks`=0 — matches every count in the reach table above).

Sensitivity proof (both directions, both encoded as tests in the file,
verified by hand against the detector function before being committed):

- **Plant** — `test_the_ast_detector_bites_a_planted_direct_import` parses
  all three real import shapes (`from dotmac_kernel.db import get_db`,
  `from dotmac_kernel import db`, `import dotmac_kernel.db`) and asserts the
  detector names each one. Confirmed by hand: all three return `True`.
- **Near-miss** — `test_the_ast_detector_does_not_flag_a_comment_or_docstring_near_miss`
  parses a synthetic module whose docstring, comment, and a string literal
  all contain the literal text `dotmac_kernel.db`, and asserts the detector
  does NOT fire, since AST detection matches only real `Import`/`ImportFrom`
  nodes. This mirrors real files already in this repo and the pinned kernel
  that name `dotmac_kernel.db` in prose without importing it (e.g.
  `dotmac_kernel/errors.py:167-182`'s comments, this repo's own
  `app/models/entrance_defaults.py:5`) — confirmed by hand: returns `False`.

Not run here (no pytest, no install, per the task's constraints) — the
subprocess-based transitive-reach assertions require the pinned kernel to be
installed (`poetry install`) and can only be exercised by CI.

## Static checks

CI runs `poetry run ruff check .` and `poetry run mypy` (`.github/workflows/ci.yml`).
Neither `ruff` nor `mypy` is installed anywhere on this machine (`command -v
ruff mypy` finds nothing; no poetry-managed virtualenv exists for this
worktree — `poetry env info -p` returns empty; no other checkout on this
machine has a matching installed `ruff`/`mypy` binary I could invoke by
absolute path). Per the task's constraint, I did not install either. Gap to
close on CI, not locally:

- `tests/architecture/test_eager_reference_runtime_reach.py` was checked by
  hand instead: `python3 -m py_compile` (passes), a manual line-length sweep
  (no line exceeds the repo's configured 120, `pyproject.toml`'s
  `[tool.ruff] line-length = 120`), and the `subprocess.run` call carries a
  `# noqa: S603` matching the exact precedent already in this repo
  (`tests/services/test_bank_lint_standalone.py:60,93`, same
  sys.executable-plus-fixed-string shape).
- The AST-detection logic and the sensitivity-proof assertions were run
  standalone with the system `python3` (no `dotmac_kernel`/`sqlalchemy`
  needed for that half — only the transitive-reach probe needs the real
  package installed, and that only happens inside CI's subprocess calls).
- I did not verify mypy type-correctness of the new test file by any means;
  report this as an open gap rather than an inferred pass.
