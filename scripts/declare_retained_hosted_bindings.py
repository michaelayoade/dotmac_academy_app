"""Declare non-secret hosted expectations before profile catalog observation.

Source-only GitHub service custody is assumed, never established or admitted.
No SQL, application imports, credentials, or target-derived expectations.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


class Unsupported(Exception):
    """The bounded hosted declaration protocol could not be satisfied."""


def require(condition: bool) -> None:
    if not condition:
        raise Unsupported


def declaration(name: str) -> str:
    value = os.environ.get("ACADEMY_RETAINED_EXPECTED_" + name)
    require(type(value) is str and 0 < len(value) <= 240)
    require(value.isascii() and value.isprintable())
    return value


def fact(docker: str, *args: str) -> str:
    # Executable and argv are controlled; never invoke a shell or expose stderr.
    result = subprocess.run(  # noqa: S603
        (docker, *args), check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30
    )
    require(0 < len(result.stdout) <= 256)
    value = result.stdout.decode("ascii").removesuffix("\n")
    require(bool(value) and value.isprintable())
    return value


def main() -> None:
    require(os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true")
    require(os.environ.get("RUNNER_OS") == "Linux")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None)
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,99}", os.environ.get("GITHUB_JOB", "")) is not None)
    container = os.environ.get("ACADEMY_RETAINED_SERVICE_CONTAINER_ID", "")
    require(re.fullmatch(r"[a-f0-9]{64}", container) is not None)
    output = Path(os.environ.get("GITHUB_ENV", ""))
    require(output.is_absolute() and output.is_file() and not output.is_symlink())

    target = declaration("TARGET_DATABASE")
    session = declaration("SETUP_SESSION")
    encoding = declaration("ENCODING")
    provider = declaration("LOCALE_PROVIDER")
    collate = declaration("LC_COLLATE")
    ctype = declaration("LC_CTYPE")
    extensions = json.loads(declaration("EXTENSION_VERSIONS"))
    require(target == "academy_retained_environment" and session == "postgres")
    require(encoding == "UTF8" and provider == "c")
    # Reviewed official PG16 Debian image protocol, not an application default.
    require(collate == "en_US.utf8" and ctype == collate)
    require(extensions == [["plpgsql", "1.0"]])

    docker = shutil.which("docker")
    require(docker is not None and Path(docker).is_absolute())
    image = fact(docker, "inspect", "--format", "{{.Image}}", container)
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image) is not None)
    binary = fact(docker, "exec", container, "postgres", "--version")
    version = re.fullmatch(
        r"postgres \(PostgreSQL\) (16)\.(0|[1-9][0-9]{0,3})(?: \([A-Za-z0-9 .+~:/_-]{1,160}\))?", binary
    )
    require(version is not None)
    libc = fact(docker, "exec", container, "getconf", "GNU_LIBC_VERSION")
    libc_version = re.fullmatch(r"glibc ([1-9][0-9]?\.[0-9]{1,3}(?:\.[0-9]{1,3})?)", libc)
    require(libc_version is not None)
    require(fact(docker, "exec", container, "printenv", "LANG") == collate)

    # PG>=10 encodes major*10000+minor. PG16 libc non-C locale versions use
    # gnu_get_libc_version(); neither value comes from the profile database.
    bindings = {
        "target_database": target,
        "setup_session": session,
        "service_image": image,
        "server_version_num": int(version[1]) * 10000 + int(version[2]),
        "encoding": encoding,
        "locale_provider": provider,
        "lc_collate": collate,
        "lc_ctype": ctype,
        "icu_locale": None,
        "collation_version": libc_version[1],
        "actual_collation_version": libc_version[1],
        "extension_versions": extensions,
    }
    values = {"academy_retained_environment_" + name: value for name, value in bindings.items()}
    require(all(re.fullmatch(r"academy_retained_environment_[a-z_]+", name) for name in values))
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    require("\n" not in encoded and "\r" not in encoded and len(encoded) <= 4096)
    with output.open("a", encoding="ascii") as stream:
        stream.write("ACADEMY_RETAINED_ENVIRONMENT_BINDINGS=" + encoded + "\n")


if __name__ == "__main__":
    try:
        main()
    except (Unsupported, OSError, ValueError, subprocess.SubprocessError):
        sys.exit("Hosted retained environment bindings unsupported; declaration refused")
