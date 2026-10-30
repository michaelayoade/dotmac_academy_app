"""Commit an independently qualified empty Academy database in hosted CI only.

The workflow provisions and marks the fixed disposable database before this
entry runs. This wrapper never supplies historical adoption authority. Its
fresh-product owner refuses an absent convergence pin; discovery cannot commit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool


class BootstrapRefused(RuntimeError):
    """Material-free failure; discard this disposable target and replay."""


def _require(condition: bool) -> None:
    if not condition:
        raise BootstrapRefused("CI composed database bootstrap refused")


def declared_target(environment: Mapping[str, str], expected_database: str) -> tuple[URL, str]:
    """Flags and environment cannot widen the fixed hosted resource boundary."""
    _require(environment.get("CI") == environment.get("GITHUB_ACTIONS") == "true")
    _require(environment.get("RUNNER_ENVIRONMENT") == "github-hosted")
    _require(environment.get("RUNNER_OS") == "Linux")
    _require(environment.get("GITHUB_REPOSITORY") == "michaelayoade/dotmac_academy_app")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    revision = environment.get("ACADEMY_CI_SOURCE_REVISION", "")
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None)
    _require(re.fullmatch(r"[1-9][0-9]{0,9}", attempt) is not None)
    _require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None)
    marker = f"academy-ci:{run_id}:{attempt}:{revision}"
    _require(environment.get("ACADEMY_CI_DATABASE_MARKER") == marker)
    _require(expected_database == "academy")
    try:
        url = make_url(environment.get("MIGRATION_DATABASE_URL", ""))
        valid = (
            url.drivername == "postgresql+psycopg"
            and url.host in ("localhost", "127.0.0.1")
            and url.port == 5437
            and url.database == expected_database
            and url.username == "app_admin"
            and not url.query
        )
    except Exception:
        raise BootstrapRefused("CI composed database bootstrap refused") from None
    _require(valid)
    _require(environment.get("MIGRATION_LOGIN_ROLE") == "app_admin")
    _require(environment.get("MIGRATION_EFFECTIVE_ROLE") == "app_admin")
    return url, marker


def _checkout_source_revision() -> str:
    result = subprocess.run(  # noqa: S603 -- fixed Git metadata read in this script's checkout
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],  # noqa: S607 -- controlled hosted runner Git
        cwd=Path(__file__).resolve().parents[1], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=True, text=True, timeout=10,
    )
    return result.stdout.strip()


def _verify_target(connection, marker: str, *, empty: bool) -> None:
    actual = connection.execute(text(
        "SELECT session_user,current_user,current_database(),"
        "pg_catalog.pg_get_userbyid(d.datdba),"
        "pg_catalog.obj_description(d.oid,'pg_database') "
        "FROM pg_catalog.pg_database d WHERE d.datname=current_database()"
    )).one()
    _require(tuple(actual) == ("app_admin", "app_admin", "academy", "app_admin", marker))
    if empty:
        count = connection.execute(text(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public'"
        )).scalar_one()
        _require(count == 0)


def bootstrap(environment: Mapping[str, str], *, expected_database: str, verify_only: bool) -> dict[str, object]:
    url, marker = declared_target(environment, expected_database)
    _require(_checkout_source_revision() == environment["ACADEMY_CI_SOURCE_REVISION"])
    # Load the product owner only after rejecting untrusted targets/declarations.
    from app.maintenance.fresh_product import run_fresh_composed_entry, verify_fresh_composed_db

    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            root = connection.begin()
            try:
                if verify_only:
                    connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                _verify_target(connection, marker, empty=not verify_only)
                if verify_only:
                    receipt = verify_fresh_composed_db(connection)
                else:
                    receipt = run_fresh_composed_entry(connection, decision_ref=marker)
                _require(connection.get_transaction() is root and root.is_active)
                _require(not connection.in_nested_transaction())
                revisions = tuple(receipt.revisions)
                digest = receipt.catalog_sha256
                _require(bool(revisions) and all(
                    type(value) is str and re.fullmatch(r"[A-Za-z0-9_]{1,100}", value) is not None
                    for value in revisions
                ))
                _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None)
                if verify_only:
                    root.rollback()
                else:
                    root.commit()
                return {"revisions": revisions, "catalog_sha256": digest}
            finally:
                if root.is_active:
                    root.rollback()
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-database", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = bootstrap(os.environ, expected_database=args.expect_database, verify_only=args.verify_only)
    except Exception:
        # SQL/driver exception bodies may contain connection or row material.
        print("CI composed database bootstrap refused; discard and replay required", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
