"""TEMPORARY names-only failure probe (remove with its single commit).

Active only when ACADEMY_NAMES_ONLY_PROBE=1. For a failing test it writes, per exception in the
``__cause__``/``__context__`` chain, ONLY: the exception class name, a five-character SQLSTATE if one
is present, and ``file:line function`` for each traceback frame under app/ or tests/. It never reads
messages, args, SQL, parameters or locals.
"""
from __future__ import annotations

import os
import re

_SQLSTATE = re.compile(r"[0-9A-Z]{5}")
_ROOT = os.getcwd()


def _sqlstate(exc: BaseException) -> str:
    for holder in (exc, getattr(exc, "orig", None)):
        value = getattr(holder, "sqlstate", None)
        if isinstance(value, str) and _SQLSTATE.fullmatch(value):
            return value
    return "-"


def _frames(exc: BaseException) -> list[str]:
    out = []
    tb = exc.__traceback__
    while tb is not None and len(out) < 60:
        code = tb.tb_frame.f_code
        path = os.path.relpath(code.co_filename, _ROOT)
        if path.startswith(("app" + os.sep, "tests" + os.sep)):
            out.append(f"{path}:{tb.tb_lineno} {code.co_name}")
        tb = tb.tb_next
    return out


def describe(exc: BaseException) -> list[str]:
    lines, seen, depth, link = [], set(), 0, "raised"
    while exc is not None and id(exc) not in seen and depth < 8:
        seen.add(id(exc))
        cls = type(exc)
        lines.append(f"PROBE[{depth}] {link} {cls.__module__}.{cls.__qualname__} sqlstate={_sqlstate(exc)}")
        lines.extend(f"PROBE[{depth}]   {frame}" for frame in _frames(exc))
        if exc.__cause__ is not None:
            exc, link = exc.__cause__, "cause"
        else:
            exc, link = exc.__context__, "context"
        depth += 1
    return lines


def pytest_exception_interact(node, call, report):
    if os.environ.get("ACADEMY_NAMES_ONLY_PROBE") != "1" or call.excinfo is None:
        return
    reporter = node.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    reporter.write_line(f"PROBE test={node.nodeid}")
    for line in describe(call.excinfo.value):
        reporter.write_line(line)
