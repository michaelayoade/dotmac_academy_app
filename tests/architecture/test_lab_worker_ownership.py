"""Static ownership guards for the lab-host cutover."""

from __future__ import annotations

import ast
from pathlib import Path

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


def test_lab_worker_systemd_unit_contains_process_containment_directives():
    unit = (ROOT / "deploy/academy-lab-worker.service").read_text()
    assert "KillMode=control-group" in unit
    assert "TimeoutStopSec=30s" in unit
    assert "SendSIGKILL=yes" in unit
