"""Every timer-driven systemd unit's ExecStart names a subcommand that exists.

`test_kernel_runtime_readiness.py` only checks that a `.service` file's
`ExecStart` contains the literal substring ``.venv/bin/python -m app.cli`` —
it never looks at what comes AFTER that, so a service whose subcommand was
misspelled, or whose subcommand was since deleted from `app/cli.py`, would
still pass that check. This module closes that gap: it parses the actual
subcommand out of each service file and checks it against the CLI's real,
registered subcommand names.

## How the CLI's registered names are resolved

`app/cli.py` registers subcommands with argparse inside ``main()``: a single
``sub = p.add_subparsers(...)`` creates the root subparsers object, and every
subcommand is a ``sub.add_parser("name", ...)`` call on THAT object (one per
subcommand, always a string literal as the first positional argument). This
module never imports `app.cli` — its docstring and
`tests/architecture/test_kernel_runtime_readiness.py` both document that
importing it is unsafe at collection time (it can eagerly reach
`dotmac_kernel.db` / `DATABASE_URL` depending on ordering). Names are
resolved purely by ``ast``, scoped deliberately narrow: only `main()`'s body
is walked, the assignment that creates the subparsers object (a call to
``.add_subparsers``) is found first, and only `.add_parser(...)` calls whose
receiver is that exact variable are counted — an `add_parser` call on some
unrelated object (a nested/independent parser, or a nonsense near-miss)
would not silently inflate the registered set. A project that later moved to
click/typer, or a plain dispatch dict, would need a different extractor here
— this one is intentionally specific to the argparse shape `app/cli.py` uses
today.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / "app" / "cli.py"

#: The one service with no paired timer and no `app.cli` ExecStart — it runs
#: `nft` directly to install a firewall table. See
#: test_kernel_runtime_readiness.py, which excludes it the same way.
HOST_FIREWALL_SERVICE = "academy-lab-ipv6-guard.service"

#: Long-running services with no timer — a systemd `Timer=` unit only makes
#: sense for something that starts, runs, and exits; these run forever under
#: `Restart=` instead. Not every `.service` is expected to have a `.timer`.
NO_TIMER_EXPECTED = {HOST_FIREWALL_SERVICE, "academy-lab-worker.service"}

_EXEC_START_CLI_RE = re.compile(r"-m app\.cli\s+([A-Za-z0-9][A-Za-z0-9-]*)")


def _find_main_function(tree: ast.Module) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return node
    raise AssertionError("app/cli.py has no top-level `def main()`")


def _find_subparsers_variable_name(main_function: ast.FunctionDef) -> str:
    """The bare name bound to `<parser>.add_subparsers(...)` inside `main()`."""
    for node in ast.walk(main_function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "add_subparsers"
        ):
            return node.targets[0].id
    raise AssertionError("main() has no `<parser>.add_subparsers(...)` assignment")


def registered_cli_subcommands(cli_path: Path = CLI_PATH) -> set[str]:
    """String literals from `<subparsers>.add_parser("name", ...)` calls inside `main()`.

    Scoped to the root subparsers object `main()` actually creates via
    `.add_subparsers(...)` — an `add_parser` call on any other receiver is
    not a real registered top-level subcommand and must not be counted.
    """
    tree = ast.parse(cli_path.read_text(encoding="utf-8"), filename=str(cli_path))
    main_function = _find_main_function(tree)
    subparsers_name = _find_subparsers_variable_name(main_function)
    names: set[str] = set()
    for node in ast.walk(main_function):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == subparsers_name
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.add(node.args[0].value)
    return names


def extract_cli_subcommand(service_text: str) -> str | None:
    """The subcommand named in an `ExecStart=... -m app.cli <subcommand>` line.

    Returns ``None`` for a service whose `ExecStart` does not invoke
    `app.cli` at all (e.g. the firewall-guard service, which runs `nft`).
    """
    for line in service_text.splitlines():
        if not line.strip().startswith("ExecStart="):
            continue
        match = _EXEC_START_CLI_RE.search(line)
        if match:
            return match.group(1)
    return None


def find_unregistered_subcommand(commands: set[str], service_text: str) -> str | None:
    """The service's subcommand if it names one `commands` does not contain.

    Returns ``None`` if the service either invokes no `app.cli` subcommand,
    or invokes one that is registered — the two "nothing wrong" cases a
    caller does not need to distinguish.
    """
    subcommand = extract_cli_subcommand(service_text)
    if subcommand is None or subcommand in commands:
        return None
    return subcommand


def test_registered_subcommands_extraction_is_not_vacuous() -> None:
    """Guard the guard: if this ever reads empty, every check below is vacuous."""
    assert registered_cli_subcommands(), "extracted zero subcommands from app/cli.py"


def test_every_app_cli_service_names_a_registered_subcommand() -> None:
    commands = registered_cli_subcommands()
    offenders: list[str] = []
    for service_file in sorted((ROOT / "deploy").glob("*.service")):
        if service_file.name == HOST_FIREWALL_SERVICE:
            continue
        text = service_file.read_text(encoding="utf-8")
        subcommand = extract_cli_subcommand(text)
        assert subcommand is not None, f"{service_file.name} has no `-m app.cli <subcommand>` ExecStart line to check"
        if subcommand not in commands:
            offenders.append(f"{service_file.name}: {subcommand!r}")
    assert not offenders, "these services name a subcommand that app/cli.py does not register:\n  " + "\n  ".join(
        offenders
    )


def _effective_timer_unit_override(timer_text: str) -> str | None:
    """The `Unit=` value inside `[Timer]`, or `None` if not overridden.

    Systemd's `.timer` unit activates whichever unit its `[Timer]` section's
    `Unit=` directive names, defaulting to the same-named `.service` only
    when `Unit=` is absent — so pairing by filename stem alone is a
    simplification that happens to hold today (every timer here declares an
    explicit same-named `Unit=`) but is not what actually decides pairing.
    Comment lines and directives outside `[Timer]` are ignored; the last
    `Unit=` assignment inside `[Timer]` wins, matching systemd itself.
    """
    current_section: str | None = None
    unit: str | None = None
    for raw_line in timer_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            continue
        if current_section != "Timer" or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip() == "Unit":
            unit = value.strip()
    return unit


def _paired_service_name(timer_file: Path) -> str:
    """The `.service` unit this timer actually activates."""
    override = _effective_timer_unit_override(timer_file.read_text(encoding="utf-8"))
    return override or f"{timer_file.stem}.service"


def test_every_timer_has_a_paired_service() -> None:
    timer_files = sorted((ROOT / "deploy").glob("*.timer"))
    assert timer_files, "expected at least one .timer unit"
    missing = sorted(
        f"{timer_file.name} -> {_paired_service_name(timer_file)}"
        for timer_file in timer_files
        if not (ROOT / "deploy" / _paired_service_name(timer_file)).is_file()
    )
    assert not missing, "these timers activate a .service file that does not exist:\n  " + "\n  ".join(missing)


def test_every_service_expected_to_have_a_timer_has_one() -> None:
    """The other direction: a periodic service with no timer would never run.

    Built from the same `Unit=`-resolved pairing above, so a timer that
    activates a differently-named service still counts toward that service.
    """
    activated_services = {_paired_service_name(timer_file) for timer_file in (ROOT / "deploy").glob("*.timer")}
    missing = sorted(
        service_file.name
        for service_file in (ROOT / "deploy").glob("*.service")
        if service_file.name not in NO_TIMER_EXPECTED and service_file.name not in activated_services
    )
    assert not missing, "these services have no paired .timer file:\n  " + "\n  ".join(missing)


def test_sensitivity_a_planted_service_with_an_unknown_subcommand_is_caught() -> None:
    commands = registered_cli_subcommands()
    planted_text = (
        "[Unit]\n"
        "Description=planted\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/home/dotmac/projects/dotmac_academy_app/.venv/bin/python -m app.cli "
        "this-subcommand-does-not-exist\n"
    )
    assert find_unregistered_subcommand(commands, planted_text) == "this-subcommand-does-not-exist"


def test_sensitivity_a_real_registered_subcommand_is_not_flagged() -> None:
    commands = registered_cli_subcommands()
    planted_text = (
        "[Service]\n" "ExecStart=/home/dotmac/projects/dotmac_academy_app/.venv/bin/python -m app.cli reap-labs\n"
    )
    assert find_unregistered_subcommand(commands, planted_text) is None


def test_sensitivity_a_non_app_cli_execstart_is_not_flagged() -> None:
    """The firewall-guard shape (no `app.cli` at all) must not read as an offender."""
    commands = registered_cli_subcommands()
    planted_text = "[Service]\nExecStart=/usr/sbin/nft --file /etc/nftables.d/example.nft\n"
    assert find_unregistered_subcommand(commands, planted_text) is None
