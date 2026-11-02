"""TEMPORARY F1 diagnostic plugin; removed by reverting its single commit.

Active only when ``ACADEMY_F1_DIAGNOSTIC=1`` (set in one CI step). It writes
material-free lines to the original stderr and never anything else:

* for failures in credential reset / password change tests, one line per
  exception link (``__cause__`` then ``__context__``, at most 6) with the class
  name, the SQLSTATE and ``file:line`` of the last frames under app/ or
  dotmac_kernel/. Never messages, args, SQL, parameters or locals.
* once (shard 1), read-only catalogue facts for D5: the owner role and the
  grantee / privilege_type / grantor role names of the lab_operations tables.
"""

from __future__ import annotations

import os
import sys
from pathlib import PurePath

import pytest

_ENABLED = os.environ.get("ACADEMY_F1_DIAGNOSTIC") == "1"
_ERROR_CLASSES = {
    "CredentialLifecycleError",
    "CredentialAuthenticatedAccountPasswordChangeError",
    "CredentialAssignmentError",
    "IdentityHistoryImportRefused",
}
_NODE_HINTS = ("reset", "password_change", "password-change", "credential_assignment")
_MAX_LINKS = 6
_MAX_FRAMES = 4


def _emit(line: str) -> None:
    print(f"F1-DIAG {line}", file=sys.__stderr__, flush=True)


def _sqlstate(exc: BaseException) -> str:
    for holder in (getattr(exc, "orig", None), exc):
        for attr in ("sqlstate", "pgcode"):
            value = getattr(holder, attr, None)
            if isinstance(value, str):
                return value
    return "-"


def _frames(exc: BaseException) -> str:
    out: list[str] = []
    tb = exc.__traceback__
    while tb is not None:
        filename = tb.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/app/" in filename or "/dotmac_kernel/" in filename:
            out.append(f"{PurePath(filename).name}:{tb.tb_lineno}")
        tb = tb.tb_next
    return ">".join(out[-_MAX_FRAMES:]) or "-"


def _links(exc: BaseException | None) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen and len(chain) < _MAX_LINKS:
        seen.add(id(exc))
        chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    return chain


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    yield
    if not _ENABLED or call.excinfo is None:
        return
    try:
        chain = _links(call.excinfo.value)
        names = {type(link).__name__ for link in chain}
        if not (names & _ERROR_CLASSES or any(hint in item.nodeid for hint in _NODE_HINTS)):
            return
        parts = [f"{type(link).__name__}[{_sqlstate(link)}]@{_frames(link)}" for link in chain]
        _emit(f"{item.nodeid} :: {call.when} :: " + " <- ".join(parts))
    except Exception as exc:  # diagnostics must never change test outcomes
        _emit(f"hook-error {type(exc).__name__}")


_CATALOGUE_QUERIES = {
    "owner": (
        "SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner) "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relname LIKE 'lab_operations%' AND c.relkind IN ('r', 'p') "
        "ORDER BY 1, 2"
    ),
    "grant": (
        "SELECT n.nspname, c.relname, "
        "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, "
        "a.privilege_type, pg_get_userbyid(a.grantor) "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "CROSS JOIN LATERAL aclexplode(c.relacl) a "
        "WHERE c.relname LIKE 'lab_operations%' AND c.relkind IN ('r', 'p') "
        "ORDER BY 1, 2, 3, 4"
    ),
}


def pytest_sessionfinish(session, exitstatus):
    if not _ENABLED or os.environ.get("SHARD_INDEX") != "1":
        return
    url = os.environ.get("TEST_MIGRATION_DATABASE_URL") or os.environ.get("TEST_DATABASE_URL")
    if not url:
        _emit("catalogue skipped: no database url")
        return
    try:
        import sqlalchemy as sa

        engine = sa.create_engine(url, hide_parameters=True, echo=False, poolclass=sa.pool.NullPool)
        try:
            with engine.connect() as connection:
                connection.execute(sa.text("SET TRANSACTION READ ONLY"))
                for label, query in _CATALOGUE_QUERIES.items():
                    for row in connection.execute(sa.text(query)).all():
                        _emit(f"catalogue {label} " + " ".join(str(value) for value in row))
        finally:
            engine.dispose()
    except Exception as exc:
        _emit(f"catalogue error {type(exc).__name__}[{_sqlstate(exc)}]")
