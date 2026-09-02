"""The identity cutover is atomic, and autogenerate can perform it by accident.

`tests/architecture/test_kernel_duplication.py` prices Academy's seven kernel
forks as a number that may only shrink. This file guards the *mechanism* that
number sits on, because measuring the fork does not stop anyone from retiring it
the wrong way — and the wrong way is one routine command.

## The forks are one unit, not seven

Two import-time properties of SQLAlchemy make the seven baseline entries a
single indivisible change. Both were verified against the kernel models at the
peeled tag `dotmac-kernel-v0.1.0a100`:

1. Academy's models reference `ForeignKey("tenants.id")` by string, resolved
   inside *their own* `MetaData`. Retiring `app/models/tenant.py:Tenant` while
   Academy keeps its own `Base` leaves that `MetaData` with no `tenants` table:

       NoReferencedTableError: Foreign key associated with column
       'people.tenant_id' could not find table 'tenants'

   So `Tenant`, `TenantDomain` and `Role` cannot be retired without also
   adopting the kernel's `Base`.

2. `from dotmac_kernel.models import Base` does not import a bare declarative
   base. Defining those classes registers ten tables into that shared
   `MetaData` as a side effect of the import. Academy's `UserCredential` then
   collides head-on:

       InvalidRequestError: Table 'user_credentials' is already defined for
       this MetaData instance.

   So adopting the kernel's `Base` cannot be done without also retiring
   `UserCredential` and `AuthSession` — and those two cannot be retired without
   the `people` -> `parties` data migration, because the kernel's versions key
   on `party_id` against a `parties` table Academy's database does not have.

The ratchet therefore cannot shrink by five, or by one. It shrinks by seven or
not at all, and the seven-at-once step is the identity programme designed in
ADR 0008, gated on Starter ADR 0017's Sub-first reference-adopter evidence.

## What autogenerate does with that

`alembic/env.py` sets `target_metadata = Base.metadata`. Swapping that `Base`
for the kernel's is a one-line edit that raises nothing at import time once the
two colliding modules are deleted — and it silently loads the autogenerate
target with five tables Academy's lineage never created, while replacing the
credential and session shape with the kernel's.

The next `alembic revision --autogenerate` then writes, unprompted:

  * `create_table` for `parties`, `party_persons`, `party_organizations`,
    `party_role_grants` and `external_identity_bindings`; and
  * `drop_column` for `user_credentials.person_id`, `.email`,
    `.failed_login_attempts`, `.locked_until` and `auth_sessions.person_id`.

That is kernel migration `0003_party_identity` — the one ADR 0008 says "must
never execute against an Academy database containing production identity" —
reconstructed under a fresh revision id, by a developer who only wanted a
migration for an unrelated column. `failed_login_attempts` and `locked_until`
are the login-lockout state the source-of-truth map assigns to
`web_auth.authenticate`; dropping them is not a schema tidy-up.

ADR 0008 guards this at the output, by rejecting migration text. That check is
half blind: it matches `create_table("parties"` on one line, and 21 of this
repository's 41 `create_table` calls put the table name on the *next* line —
including `0053`, and including everything `--autogenerate` emits for a table
with more than a couple of columns. The scanner below is AST-based for exactly
that reason, and `test_the_migration_scanner_is_not_defeated_by_line_wrapping`
holds the difference in place.

## Why these detectors are not vacuous

The forbidden set is derived, never hardcoded: it is *the installed kernel's own
tables* minus the tables the duplication baseline says Academy legitimately
shares. It tracks the kernel's surface as it moves — `party_roles` became
`party_role_grants` and `external_identity_bindings` appeared between a38 and
a100, and neither needed an edit here.

It is also deliberately not `kernel_tables - academy_target_tables`, which would
be self-defeating: adopting the kernel's `Base` makes those two sets equal and
the check would pass at the exact moment it should fail.

Every detector is a module-level function taking its input as an argument, so
the sensitivity tests can aim it at a synthetic offender. A guard never observed
failing is not known to work.
"""

from __future__ import annotations

import ast
import pathlib

import dotmac_kernel.models as kernel_models
from sqlalchemy import Column, ForeignKey, MetaData, String, Table
from sqlalchemy import Uuid as SAUuid

import app.models  # noqa: F401  (registers most Academy tables on the shared Base)
from app.models import (  # noqa: F401  (env.py registers these; __init__ does not export them all)
    admissions,
    assessment,
    auth,
    class_session,
    cohort,
    course,
    onboarding,
    person,
    rbac,
    tenant,
)
from app.models.base import Base

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS = REPO_ROOT / "alembic" / "versions"
ALEMBIC_ENV = REPO_ROOT / "alembic" / "env.py"
BASELINE = pathlib.Path(__file__).with_name("kernel_duplication_baseline.txt")

#: Columns that carry Academy-owned identity or security state on the two tables
#: whose name Academy shares with the kernel but whose *shape* it does not. The
#: kernel's versions of these tables key on `party_id`; Academy's key on
#: `person_id` and additionally own the login-lockout state.
ACADEMY_OWNED_IDENTITY_COLUMNS = {
    "user_credentials": {"person_id", "email", "failed_login_attempts", "locked_until"},
    "auth_sessions": {"person_id"},
}

#: The column that would replace them. Its presence in Academy's autogenerate
#: target means the cutover has started.
KERNEL_IDENTITY_COLUMN = "party_id"


# --------------------------------------------------------------------------- #
# Detectors. Each takes its input, so a sensitivity test can point it at a
# synthetic offender rather than trusting that it would have noticed one.
# --------------------------------------------------------------------------- #


def _baseline_entries() -> set[str]:
    return {
        line.strip()
        for line in BASELINE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def shared_identity_tables() -> set[str]:
    """Tables Academy legitimately shares with the kernel, per the ratchet.

    Resolved through each baseline class's real ``__tablename__`` rather than by
    guessing a name from the class, so a rename cannot slip past. Baseline
    entries that map to no table (``Base``, ``TimestampMixin``) contribute
    nothing.
    """
    modules = {
        "app/models/tenant.py": tenant,
        "app/models/auth.py": auth,
        "app/models/rbac.py": rbac,
    }
    tables: set[str] = set()
    for entry in _baseline_entries():
        path, _, class_name = entry.partition(":")
        module = modules.get(path)
        if module is None:
            continue
        model = getattr(module, class_name, None)
        table_name = getattr(model, "__tablename__", None)
        if isinstance(table_name, str):
            tables.add(table_name)
    return tables


def kernel_only_tables() -> set[str]:
    """Kernel tables Academy's lineage has never created.

    Derived from the *installed* kernel so it tracks that package's surface, and
    subtracted from the ratchet rather than from Academy's own metadata, which
    would make the check pass exactly when the fork was retired.
    """
    return set(kernel_models.Base.metadata.tables) - shared_identity_tables()


def phantom_tables(target_metadata: MetaData, forbidden: set[str]) -> set[str]:
    """Forbidden tables present in an autogenerate target."""
    return set(target_metadata.tables) & forbidden


def identity_shape_faults(target_metadata: MetaData) -> list[str]:
    """Ways the shared identity tables have drifted towards the kernel's shape."""
    faults: list[str] = []
    for table_name, owned in sorted(ACADEMY_OWNED_IDENTITY_COLUMNS.items()):
        table = target_metadata.tables.get(table_name)
        if table is None:
            faults.append(f"{table_name}: absent from the autogenerate target")
            continue
        present = {column.name for column in table.columns}
        for column_name in sorted(owned - present):
            faults.append(f"{table_name}.{column_name}: Academy-owned column is gone")
        if KERNEL_IDENTITY_COLUMN in present:
            faults.append(f"{table_name}.{KERNEL_IDENTITY_COLUMN}: kernel identity column has appeared")
    return faults


def upgrade_calls(source: str) -> list[ast.Call]:
    """Every call reachable from ``upgrade()``, following module-level helpers.

    Neither obvious scope is right on its own, and both failure modes are real
    in this repository:

    * ``upgrade()``'s body alone misses `0001`, which builds every identity
      table inside module-level ``_create_tenants_table``-style helpers; and
    * the whole module wrongly indicts `0041`, whose ``upgrade()`` *adds*
      ``failed_login_attempts`` and ``locked_until`` and whose ``downgrade()``
      drops them again. That is symmetric authorship, not a cutover.

    So: start at ``upgrade``, follow calls to module-level functions
    transitively, and never enter ``downgrade``. A module with no ``upgrade``
    is scanned whole, which is what makes a bare snippet testable.
    """
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if "upgrade" not in functions:
        return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    seen: set[str] = set()
    pending = ["upgrade"]
    calls: list[ast.Call] = []
    while pending:
        name = pending.pop()
        if name in seen or name not in functions:
            continue
        seen.add(name)
        for node in ast.walk(functions[name]):
            if not isinstance(node, ast.Call):
                continue
            calls.append(node)
            if isinstance(node.func, ast.Name) and node.func.id in functions:
                pending.append(node.func.id)
    return calls


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _string_arg(node: ast.Call, index: int) -> str | None:
    if len(node.args) <= index:
        return None
    arg = node.args[index]
    return arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None


def created_tables(source: str) -> set[str]:
    """Every table name passed to a ``create_table`` call reachable from upgrade."""
    return {
        name
        for node in upgrade_calls(source)
        if _call_name(node) == "create_table" and (name := _string_arg(node, 0)) is not None
    }


def dropped_columns(source: str) -> set[tuple[str, str]]:
    """Every ``(table, column)`` dropped on the way up."""
    found: set[tuple[str, str]] = set()
    for node in upgrade_calls(source):
        if _call_name(node) != "drop_column":
            continue
        table, column = _string_arg(node, 0), _string_arg(node, 1)
        if table is not None and column is not None:
            found.add((table, column))
    return found


def _migration_sources() -> dict[pathlib.Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in sorted(MIGRATIONS.glob("*.py"))}


def kernel_requires_web_facets() -> bool:
    """Does the INSTALLED kernel route legacy `web_routers` through facets?

    Asked of the installed package rather than of its version string, because a
    version string is a spelling and this is the thing.
    """
    try:
        import dotmac_kernel.web_surfaces as web_surfaces
    except ImportError:
        return False
    return hasattr(web_surfaces, "WebSurfaceRegistry")


def _assembly_declaration() -> dict[str, ast.expr]:
    """The keyword arguments of the `ProductAssemblySpec(...)` call, by AST.

    Read rather than imported: this gate should not have to construct every
    router in the product to answer a question about a declaration.
    """
    tree = ast.parse((REPO_ROOT / "app" / "assembly.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ProductAssemblySpec"
        ):
            return {kw.arg: kw.value for kw in node.keywords if kw.arg}
    raise AssertionError("app/assembly.py declares no ProductAssemblySpec")


def web_facet_gap(*, kernel_requires_facets: bool, web_enabled: bool, declares_facets: bool) -> str | None:
    """The composition fault a kernel upgrade past a95 would produce here."""
    if not kernel_requires_facets:
        return None
    if not web_enabled:
        return None
    if declares_facets:
        return None
    return (
        "the installed kernel composes browser routes through WebSurfaceRegistry, "
        "which refuses legacy web_routers unless the assembly declares a secured "
        "staff_admin facet"
    )


def _env_registered_model_modules() -> set[str]:
    """The `app.models.*` submodules `alembic/env.py` imports for autogenerate."""
    tree = ast.parse(ALEMBIC_ENV.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "app.models":
            modules.update(alias.name for alias in node.names)
    return modules


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #


def test_academy_still_owns_its_declarative_base() -> None:
    """The cutover is atomic and gated; this is where it would start."""
    assert Base is not kernel_models.Base, (
        "app/models/base.py:Base has been replaced by the kernel's.\n\n"
        "That single edit is the whole identity cutover, not a step towards it: "
        "importing the kernel's Base registers its identity tables into the "
        "shared MetaData, which collides with Academy's UserCredential and "
        "AuthSession, and loads alembic's autogenerate target with tables this "
        "database has never had.\n\n"
        "ADR 0008 sequences this as an expand/shadow/cutover/contract programme "
        "and gates it on Starter ADR 0017's Sub-first reference-adopter "
        "evidence. It is not a seven-line import substitution."
    )


def test_this_gate_watches_the_same_models_autogenerate_does() -> None:
    """Guard the guard: if env.py registers more, this file must too.

    A model module registered by `alembic/env.py` but not imported here would be
    in the real autogenerate target and outside every check below.
    """
    watched = {
        "admissions",
        "assessment",
        "auth",
        "class_session",
        "cohort",
        "course",
        "onboarding",
        "person",
        "rbac",
        "tenant",
    }
    assert _env_registered_model_modules() == watched, (
        "alembic/env.py's model registrations have changed. Import the same set "
        "here, or this gate inspects a narrower metadata than autogenerate does."
    )


def test_the_autogenerate_target_holds_no_kernel_only_identity_table() -> None:
    """No table in Academy's autogenerate target that its lineage never created."""
    found = phantom_tables(Base.metadata, kernel_only_tables())
    assert not found, (
        "These kernel tables are in Academy's autogenerate target but were never "
        "created by an Academy migration:\n  " + "\n  ".join(sorted(found)) + "\n\n"
        "The next `alembic revision --autogenerate` will emit CREATE TABLE for "
        "each of them. That is kernel 0003_party_identity by another name; see "
        "ADR 0008."
    )


def test_the_shared_identity_tables_keep_their_academy_shape() -> None:
    """Name-sharing is allowed; shape-sharing means the cutover has begun."""
    faults = identity_shape_faults(Base.metadata)
    assert not faults, (
        "Academy's identity tables have drifted towards the kernel's shape:\n  "
        + "\n  ".join(faults)
        + "\n\nfailed_login_attempts and locked_until are the login-abuse state "
        "the source-of-truth map assigns to web_auth.authenticate. They do not "
        "move without the ADR 0008 backfill."
    )


def test_no_migration_creates_a_kernel_only_identity_table() -> None:
    """The output half: nothing may hand-write or autogenerate the cutover."""
    forbidden = kernel_only_tables()
    offenders = {
        path.name: sorted(created_tables(source) & forbidden)
        for path, source in _migration_sources().items()
        if created_tables(source) & forbidden
    }
    assert not offenders, (
        f"These migrations create kernel identity tables: {offenders}\n\n"
        "Academy's lineage does not own them. See ADR 0008."
    )


def test_no_migration_drops_an_academy_owned_identity_column() -> None:
    """The destructive half of the same reconstructed migration."""
    protected = {
        (table, column)
        for table, columns in ACADEMY_OWNED_IDENTITY_COLUMNS.items()
        for column in columns
    }
    offenders = {
        path.name: sorted(dropped_columns(source) & protected)
        for path, source in _migration_sources().items()
        if dropped_columns(source) & protected
    }
    assert not offenders, (
        f"These migrations drop Academy-owned identity or lockout state: {offenders}\n\n"
        "The fallback release still reads these columns. See ADR 0008's "
        "expand/shadow/cutover/contract sequence."
    )


def test_the_kernel_pin_stays_below_the_facet_wall() -> None:
    """The pin bump and the identity cutover are the same change from a97 on.

    Kernel a38..a95 mount a `FeatureManifest`'s `web_routers` directly:

        mount_features(app, manifests=..., disabled=..., web_enabled=web_enabled)

    From a97 that call is hard-coded `web_enabled=False` and browser routes go
    through `WebSurfaceRegistry`, which refuses legacy `web_routers` without a
    `staff_admin` facet carrying both an authentication profile and an admission
    permission. That admission runs `authorize_party`, i.e.

        SELECT ... FROM party_role_grants JOIN roles ...

    on every composed browser request, and the profile must return a
    `dotmac_kernel.models.Party`. Academy has no `parties` and no
    `party_role_grants`, so from a97 the pin bump *is* the identity cutover for
    any deployment keeping its admin UI — and that cutover is gated by ADR 0008.

    `web_enabled=False` escapes the wall by dropping all 27 of Academy's web
    routers. That is not an upgrade, so it is not the way through.
    """
    declaration = _assembly_declaration()
    web_enabled_node = declaration.get("web_enabled")
    web_enabled = not (isinstance(web_enabled_node, ast.Constant) and web_enabled_node.value is False)

    gap = web_facet_gap(
        kernel_requires_facets=kernel_requires_web_facets(),
        web_enabled=web_enabled,
        declares_facets="web_facets" in declaration,
    )
    assert gap is None, (
        f"{gap}.\n\n"
        "a95 is the highest kernel this assembly can take until the ADR 0008 "
        "identity programme lands. Pin no higher, or declare the facet — which "
        "requires the parties/roles/party_role_grants schema and is therefore "
        "the cutover, not a pin bump."
    )


# --------------------------------------------------------------------------- #
# Sensitivity proofs. Each detector must be observed failing on an offender and
# passing on the legitimate case.
# --------------------------------------------------------------------------- #


def test_the_facet_gap_detector_fires_only_on_the_real_combination() -> None:
    """Observed failing: a post-a96 kernel under Academy's actual declaration."""
    assert web_facet_gap(kernel_requires_facets=True, web_enabled=True, declares_facets=False)
    # ...and stays silent on each legitimate escape.
    assert web_facet_gap(kernel_requires_facets=False, web_enabled=True, declares_facets=False) is None
    assert web_facet_gap(kernel_requires_facets=True, web_enabled=False, declares_facets=False) is None
    assert web_facet_gap(kernel_requires_facets=True, web_enabled=True, declares_facets=True) is None


def test_the_assembly_declaration_is_actually_readable() -> None:
    """A declaration reader that silently found nothing would pass everything."""
    declaration = _assembly_declaration()
    assert declaration["tenancy"].value == "single"
    assert declaration["platform_surface_enabled"].value is False
    assert "modules" in declaration


def _synthetic_cutover_metadata() -> MetaData:
    """What Academy's autogenerate target becomes once `Base` is the kernel's.

    Built by hand rather than by importing the kernel's Base, so the offender is
    a fixed shape that stays an offender even if the kernel's models move.
    """
    metadata = MetaData()
    Table("parties", metadata, Column("id", SAUuid(), primary_key=True))
    Table(
        "user_credentials",
        metadata,
        Column("id", SAUuid(), primary_key=True),
        Column("party_id", SAUuid(), ForeignKey("parties.id"), nullable=False),
        Column("password_hash", String(255), nullable=False),
    )
    Table(
        "auth_sessions",
        metadata,
        Column("id", SAUuid(), primary_key=True),
        Column("party_id", SAUuid(), ForeignKey("parties.id"), nullable=False),
    )
    return metadata


def test_the_phantom_table_detector_fails_on_a_synthetic_cutover() -> None:
    offender = _synthetic_cutover_metadata()
    assert phantom_tables(offender, {"parties", "party_persons"}) == {"parties"}
    # ...and does not fire on the real, legitimate target.
    assert phantom_tables(Base.metadata, {"parties", "party_persons"}) == set()


def test_the_shape_detector_fails_on_a_synthetic_party_id_swap() -> None:
    faults = identity_shape_faults(_synthetic_cutover_metadata())
    assert any("user_credentials.party_id" in fault for fault in faults)
    assert any("user_credentials.person_id" in fault for fault in faults)
    assert any("auth_sessions.party_id" in fault for fault in faults)
    assert any("locked_until" in fault for fault in faults)
    # ...and stays silent on the real target.
    assert identity_shape_faults(Base.metadata) == []


def test_the_migration_scanner_is_not_defeated_by_line_wrapping() -> None:
    """The specific defect this file exists to close.

    ADR 0008's design-only guard tests `'create_table("parties"' not in source`.
    `--autogenerate` wraps any table with more than a couple of columns, and so
    does this repository's own formatting, which puts the name on the next line
    in 21 of its 41 `create_table` calls.
    """
    wrapped = (
        "def upgrade() -> None:\n"
        "    op.create_table(\n"
        '        "parties",\n'
        '        sa.Column("id", sa.Uuid(), nullable=False),\n'
        "    )\n"
    )
    assert 'create_table("parties"' not in wrapped, "the string match's blind spot"
    assert created_tables(wrapped) == {"parties"}, "the AST scanner must still see it"

    single_quoted = "op.create_table('parties', sa.Column('id', sa.Uuid()))\n"
    assert created_tables(single_quoted) == {"parties"}

    # A legitimate Academy migration must not trip it.
    assert created_tables('op.create_table(\n    "tenant_entrance_defaults",\n)\n') == {
        "tenant_entrance_defaults"
    }


def test_the_drop_column_scanner_sees_a_wrapped_destructive_drop() -> None:
    wrapped = 'def upgrade():\n    op.drop_column(\n        "user_credentials",\n        "locked_until",\n    )\n'
    assert dropped_columns(wrapped) == {("user_credentials", "locked_until")}
    assert dropped_columns('op.drop_column("courses", "subtitle")\n') == {("courses", "subtitle")}


def test_the_comparison_tracks_the_installed_kernel_and_is_not_empty() -> None:
    """A check over an empty set passes for the wrong reason."""
    assert kernel_models.Base.metadata.tables, "installed kernel defines no tables"
    assert Base.metadata.tables, "Academy's autogenerate target is empty"
    assert shared_identity_tables() == {
        "tenants",
        "tenant_domains",
        "roles",
        "user_credentials",
        "auth_sessions",
    }, "the ratchet's table-backed entries have moved; re-read the baseline"
    assert "parties" in kernel_only_tables(), "the forbidden set has stopped naming the identity core"
    assert _migration_sources(), "no migrations found to scan"
