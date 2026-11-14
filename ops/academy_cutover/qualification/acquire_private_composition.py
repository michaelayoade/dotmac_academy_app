"""Acquire an immutable private qualification bundle; never render its contents."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPOSITORY = "michaelayoade/dotmac_academy_console_fixtures"
COMMIT = "1fbdc9cd5c45a768c65bbd0adfe20defd5992c82"
BUNDLE_SHA256 = "4d4003b8d56ebd6deb0237510679fe5c89462163d4d98a5411a8ac8b26a51d8b"
LIMIT = 2 * 1024 * 1024


def require(value: bool) -> None:
    if not value:
        raise ValueError("private qualification refused")


def main() -> None:
    secret = os.environ.pop("ACADEMY_WEBFIG_FIXTURE_SSH_KEY", "")
    require(bool(secret.strip()) and re.fullmatch(r"[0-9a-f]{40}", COMMIT) is not None)
    spec = importlib.util.spec_from_file_location(
        "bounded_fixture_transport", ROOT / "scripts/materialize_webfig_fixtures.py"
    )
    require(spec is not None and spec.loader is not None)
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    with tempfile.TemporaryDirectory(prefix="private-composition-transport-", dir="/tmp") as directory:
        work = Path(directory)
        key = work / "identity"
        key.touch(mode=0o600)
        key.write_text(secret.rstrip() + "\n")
        secret = ""
        host = work / "known_hosts"
        host.write_bytes((ROOT / ".github/private-fixtures/github_known_hosts").read_bytes())
        ssh = shlex.join([
            "/usr/bin/ssh", "-F", "/dev/null", "-i", str(key), "-T", "-oBatchMode=yes",
            "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oForwardAgent=no", "-oClearAllForwardings=yes",
            "-oStrictHostKeyChecking=yes", f"-oUserKnownHostsFile={host}", "-oGlobalKnownHostsFile=/dev/null",
            "-oHostKeyAlgorithms=ssh-ed25519", "-oConnectTimeout=30",
        ])
        env = {
            "PATH": "/usr/bin:/bin", "HOME": str(work), "XDG_CONFIG_HOME": str(work),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "GIT_SSH_COMMAND": ssh, "GIT_SSH_VARIANT": "ssh", "GIT_ALLOW_PROTOCOL": "ssh",
            "GIT_LFS_SKIP_SMUDGE": "1", "LC_ALL": "C",
        }
        repo = work / "repo.git"
        repo.mkdir()
        transport.git(repo, env, "init", "--bare", "--template=")
        transport.git(repo, env, "fetch", "--no-tags", "--no-recurse-submodules", "--depth=1",
                      f"git@github.com:{REPOSITORY}.git", COMMIT)
        require(transport.git(repo, env, "rev-parse", "FETCH_HEAD").decode().strip() == COMMIT)
        oid = transport.git(repo, env, "rev-parse", f"{COMMIT}:reader-composition/bundle.tar.gz").decode().strip()
        require(re.fullmatch(r"[0-9a-f]{40}", oid) is not None)
        raw = transport.read_blob(repo, env, oid)
        require(hashlib.sha256(raw).hexdigest() == BUNDLE_SHA256)
    # The SSH key and object store are gone before any private code is materialized.
    destination = Path(os.environ["RUNNER_TEMP"]) / "private-reader-composition"
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        require(1 <= len(members) <= 32)
        names = set()
        total = 0
        for member in members:
            require(member.isfile() and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", member.name) is not None)
            require(member.name not in names and 0 < member.size <= LIMIT)
            names.add(member.name)
            total += member.size
            require(total <= 4 * LIMIT)
            source = archive.extractfile(member)
            require(source is not None)
            with source:
                content = source.read(LIMIT + 1)
            require(len(content) == member.size)
            fd = os.open(destination / member.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
    manifest = json.loads((destination / "source-manifest.json").read_bytes())
    require(type(manifest) is dict and set(manifest) | {"source-manifest.json"} == names)
    for name, sha in manifest.items():
        require(hashlib.sha256((destination / name).read_bytes()).hexdigest() == sha)
    print("Private composition source verified; contents withheld.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Private composition acquisition refused; contents withheld.") from None
