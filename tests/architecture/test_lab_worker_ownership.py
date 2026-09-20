"""Static ownership guards for the lab-host cutover."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _imports_concrete_engine(source: str) -> bool:
    tree = ast.parse(source)
    return any(
        (
            isinstance(node, ast.ImportFrom)
            and (node.module or "").startswith("app.services.labengine")
            and any(alias.name == "ContainerlabEngine" for alias in node.names)
        )
        or (
            isinstance(node, ast.Import)
            and any(
                alias.name.startswith("app.services.labengine")
                for alias in node.names
            )
        )
        for node in ast.walk(tree)
    )


def test_concrete_engine_import_guard_detects_alias_forms():
    assert _imports_concrete_engine(
        "from app.services.labengine import ContainerlabEngine as Engine"
    )
    assert _imports_concrete_engine(
        "import app.services.labengine.containerlab as containerlab"
    )


def test_web_routes_do_not_import_the_concrete_engine():
    offenders = {
        str(path.relative_to(ROOT))
        for path in (ROOT / "app/web").rglob("*.py")
        if _imports_concrete_engine(path.read_text())
    }
    assert offenders == set()


def test_only_the_worker_cli_imports_the_concrete_containerlab_engine():
    importers: set[str] = set()
    for path in (ROOT / "app").rglob("*.py"):
        relative = str(path.relative_to(ROOT))
        if relative.startswith("app/services/labengine/"):
            continue
        if _imports_concrete_engine(path.read_text()):
            importers.add(relative)
    assert importers == {"app/cli.py"}


def test_reaper_cli_is_engine_free():
    source = (ROOT / "app/cli.py").read_text()
    tree = ast.parse(source)
    reap = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_reap_labs"
    )
    body = ast.get_source_segment(source, reap) or ""
    assert "ContainerlabEngine" not in body
    assert "labengine" not in body
    assert "request_idle_reaps" in body


def _references_name(function_node: ast.FunctionDef, name: str) -> bool:
    """True if ``name`` appears as an identifier anywhere in the function body.

    Matches a bare reference (``admin_session``) or an attribute access
    (``lab_jobs.admin_session``) — either form would mean the wrong,
    non-worker session got used for containerlab work.
    """
    return any(
        (isinstance(node, ast.Name) and node.id == name)
        or (isinstance(node, ast.Attribute) and node.attr == name)
        for node in ast.walk(function_node)
    )


def test_lab_host_commands_use_the_dedicated_worker_session_only():
    source = (ROOT / "app/cli.py").read_text()
    tree = ast.parse(source)
    functions = {}
    bodies = {}
    for name in ("_lab_worker", "_lab_reconcile", "_reap_labs"):
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        functions[name] = function
        bodies[name] = ast.get_source_segment(source, function) or ""
    assert "lab_worker_session" in bodies["_lab_worker"]
    assert "lab_worker_session" in bodies["_lab_reconcile"]
    assert "lab_worker_session" not in bodies["_reap_labs"]
    # A substring check on "lab_worker_session" alone would still pass if
    # these functions ALSO called admin_session (the wrong, non-worker
    # session) for containerlab work — require exclusivity, not just presence.
    assert not _references_name(functions["_lab_worker"], "admin_session")
    assert not _references_name(functions["_lab_reconcile"], "admin_session")

    jobs_source = (ROOT / "app/services/lab_jobs.py").read_text()
    assert "settings.lab_worker_database_url" in jobs_source
    assert 'SELECT current_user' in jobs_source


def test_systemd_units_declare_opposite_host_roles():
    worker = (ROOT / "deploy/academy-lab-worker.service").read_text()
    reaper = (ROOT / "deploy/academy-reap-labs.service").read_text()
    reconciler = (ROOT / "deploy/academy-lab-reconcile.service").read_text()
    assert "Environment=LAB_HOST_ROLE=lab" in worker
    assert "Environment=LAB_HOST_ROLE=web" in reaper
    assert "Environment=LAB_HOST_ROLE=lab" in reconciler


def test_lab_reconcile_has_a_periodic_timer():
    timer = (ROOT / "deploy/academy-lab-reconcile.timer").read_text()
    assert "OnUnitActiveSec=1min" in timer
    assert "Unit=academy-lab-reconcile.service" in timer
    assert "WantedBy=timers.target" in timer


def test_only_the_worker_acquires_the_lifetime_singleton_lock():
    """worker_singleton_lock is a whole-process-lifetime lock; the reconciler
    must keep contending only on the shorter-lived per-operation host_lock,
    never on this one — merging the two would make every 1-minute reconcile
    pass contend against the worker's own permanent hold of it.
    """
    source = (ROOT / "app/cli.py").read_text()
    tree = ast.parse(source)
    functions = {}
    bodies = {}
    for name in ("_lab_worker", "_lab_reconcile"):
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        functions[name] = function
        bodies[name] = ast.get_source_segment(source, function) or ""
    assert "worker_singleton_lock" in bodies["_lab_worker"]
    assert "worker_singleton_lock" not in bodies["_lab_reconcile"]


def _effective_section_directives(unit_text: str, section: str) -> dict[str, str]:
    """Effective ``key -> value`` directives inside a single ``[section]``.

    Systemd unit files use ``#`` (and ``;``) for whole-line comments, so a
    directive that has been commented out — e.g. ``# KillMode=control-group``
    — must not be treated as present just because the substring still
    appears somewhere in the raw file text.

    A directive only takes effect when it is inside the named section, and
    when a key is assigned more than once within that section, systemd's own
    parser applies last-assignment-wins semantics — so a later conflicting
    line for the same key must overwrite an earlier one here too.
    """
    directives: dict[str, str] = {}
    current_section: str | None = None
    for raw_line in unit_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            continue
        if current_section != section or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        directives[key.strip()] = value.strip()
    return directives


def test_lab_worker_systemd_unit_contains_process_containment_directives():
    unit = (ROOT / "deploy/academy-lab-worker.service").read_text()
    service_directives = _effective_section_directives(unit, "Service")
    assert service_directives.get("KillMode") == "control-group"
    assert service_directives.get("TimeoutStopSec") == "30s"
    assert service_directives.get("SendSIGKILL") == "yes"


@pytest.mark.parametrize(
    "commented_directive",
    ["KillMode=control-group", "TimeoutStopSec=30s", "SendSIGKILL=yes"],
)
def test_effective_section_directives_rejects_a_commented_out_directive(
    commented_directive,
):
    """A directive that has been commented out must not read as active.

    This is the regression the old, unanchored substring check
    (``assert "KillMode=control-group" in unit``) could not catch: the
    substring stays present in the raw file text even when the line is
    ``# KillMode=control-group``, so that check would pass against a unit
    file where the directive had been silently disabled.
    """
    key, _, value = commented_directive.partition("=")
    unit_text = (
        "[Service]\n"
        f"# {commented_directive}\n"
        "OtherDirective=value\n"
    )
    assert _effective_section_directives(unit_text, "Service").get(key) != value


def test_effective_section_directives_ignores_directives_outside_the_section():
    """A directive that lives outside ``[Service]`` never takes effect there.

    A flat, section-blind scan of the file would treat this line as present
    simply because the exact text appears somewhere in the file, even though
    real systemd would never apply a ``[Service]``-only directive found under
    ``[Unit]`` or after ``[Install]``.
    """
    unit_text = (
        "[Unit]\n"
        "KillMode=control-group\n"
        "\n"
        "[Service]\n"
        "TimeoutStopSec=30s\n"
        "\n"
        "[Install]\n"
        "SendSIGKILL=yes\n"
    )
    service_directives = _effective_section_directives(unit_text, "Service")
    assert service_directives.get("KillMode") is None
    assert service_directives.get("SendSIGKILL") is None
    assert service_directives.get("TimeoutStopSec") == "30s"


def test_effective_section_directives_resolves_conflicts_last_assignment_wins():
    """A later conflicting assignment for the same key wins, matching systemd.

    A ``set`` of whole lines has no notion of order, so both the original
    and a later, conflicting override would show up as independently
    "present" and a membership check on the first value would stay green
    even though the real effective config is the later value.
    """
    unit_text = (
        "[Service]\n"
        "KillMode=control-group\n"
        "KillMode=process\n"
    )
    service_directives = _effective_section_directives(unit_text, "Service")
    assert service_directives.get("KillMode") == "process"
