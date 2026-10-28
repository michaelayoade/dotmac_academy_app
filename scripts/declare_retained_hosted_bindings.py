"""Project separately PREdeclared non-secret environment/history/assembly data.

No SQL, Docker, observed target, DSN or current_database retargeting. This data
cannot authenticate a service, GitHub origin, access fence or resource owner.
Root CI chooses and verifies the immutable OCI image and platform separately.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


class Unsupported(Exception):
    """Incomplete or contradictory predeclaration; do not write partial output."""


def require(condition: bool) -> None:
    if not condition:
        raise Unsupported


def declaration(name: str) -> str:
    value = os.environ.get("ACADEMY_RETAINED_EXPECTED_" + name)
    require(type(value) is str and 0 < len(value) <= 1024)
    require(value.isascii() and value.isprintable())
    return value


def declarations() -> dict[str, object]:
    """Every rendering input is declared before creation, never learned by SQL."""
    image = declaration("SERVICE_IMAGE")
    platform = declaration("PLATFORM")
    require(re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image) is not None)
    require(platform in ("linux/amd64", "linux/arm64"))
    version = declaration("SERVER_VERSION_NUM")
    require(re.fullmatch(r"16[0-9]{4}", version) is not None)
    fields = {
        "setup_session": declaration("SETUP_SESSION"),
        "service_image": image,
        "server_version_num": int(version),
        "encoding": declaration("ENCODING"),
        "locale_provider": declaration("LOCALE_PROVIDER"),
        "lc_collate": declaration("LC_COLLATE"),
        "lc_ctype": declaration("LC_CTYPE"),
        "icu_locale": json.loads(declaration("ICU_LOCALE")),
        "collation_version": json.loads(declaration("COLLATION_VERSION")),
        "actual_collation_version": json.loads(declaration("ACTUAL_COLLATION_VERSION")),
        "extension_versions": json.loads(declaration("EXTENSION_VERSIONS")),
    }
    require(fields["setup_session"] == "postgres" and fields["encoding"] == "UTF8")
    require(fields["locale_provider"] == "c" and fields["icu_locale"] is None)
    require(fields["lc_collate"] == fields["lc_ctype"] == "en_US.utf8")
    require(type(fields["collation_version"]) is str and bool(fields["collation_version"]))
    require(fields["collation_version"] == fields["actual_collation_version"])
    require(fields["extension_versions"] == [["plpgsql", "1.0"]])
    result = {"image": image, "platform": platform}
    targets = []
    for purpose in ("environment", "history", "assembly"):
        target = declaration(purpose.upper() + "_TARGET_DATABASE")
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", target) is not None)
        targets.append(target)
        result[purpose] = {
            "academy_retained_environment_" + name: value
            for name, value in {"target_database": target, **fields}.items()
        }
    require(len(set(targets)) == 3)
    return result


def main() -> None:
    require(os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true")
    # These strings are preflight only; actual repository/workflow/job/run
    # authority is externally verified by Root, never by this declaration.
    output = Path(os.environ.get("GITHUB_ENV", ""))
    require(output.is_absolute() and output.is_file() and not output.is_symlink())
    values = declarations()
    lines = []
    for purpose in ("environment", "history", "assembly"):
        encoded = json.dumps(values[purpose], ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        require("\n" not in encoded and "\r" not in encoded and len(encoded) <= 4096)
        lines.append("ACADEMY_RETAINED_" + purpose.upper() + "_BINDINGS=" + encoded)
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    require("\n" not in encoded and "\r" not in encoded and len(encoded) <= 16384)
    lines.append("ACADEMY_HOSTED_GENESIS_DECLARATION=" + encoded)
    with output.open("a", encoding="ascii") as stream:
        stream.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (Unsupported, OSError, ValueError):
        sys.exit("Hosted retained bindings unsupported; declaration refused")
