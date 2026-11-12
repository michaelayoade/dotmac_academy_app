"""Hosted-only exact-source app-sync capture; public outputs contain ciphertext/hashes.

Never imports the product. The isolated child imports only the SHA-pinned build
backend. No publish/tag/install/index credentials, private keys or fixture reads.
The root coordinator alone reviews/decrypts the retained age v1 artifact.
"""

import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ACADEMY_CANDIDATE = "dfe85eae52133d2d7cba8df82b990030dc958307"
ACADEMY_TREE = "892fbce24c851571c210eef645dc28af05dc5bf8"
SOURCE_URL = "https://github.com/michaelayoade/dotmac_starter_mt.git"
SOURCE_COMMIT = "e1bfa54e23bd8184c20beb2dc1d9f0938fa336f6"
SOURCE_SUBDIR = "packages/dotmac-app-sync"
STAGED_WHEEL_SHA256 = "2b8df470ccaa1b830cffae2d6370b226b2c53bbf8685e5d81903e81c5fbead38"
BACKEND_VERSION = "2.5.0"
BACKEND_FILENAME = "poetry_core-2.5.0-py3-none-any.whl"
BACKEND_SHA256 = "98ee465b66f7e14bb9fbe68fb5e00d0cff184f036993ec94610ae4b5612f3add"
BACKEND_URL = (
    "https://files.pythonhosted.org/packages/b7/25/"
    "7ed0a2ea4fe12f7fd0394387b5debbcd6fdbd06e5ac9daab96ba11471da8/" + BACKEND_FILENAME
)
AGE_VERSION = "1.3.2"
AGE_URL = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz"
# Official release API asset.digest, independently read during source review:
# https://api.github.com/repos/FiloSottile/age/releases/tags/v1.3.2
AGE_ARCHIVE_SHA256 = "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"
RECIPIENT_PATH = Path(".github/artifact-provenance-recipient.txt")
RECIPIENT_FILE_SHA256 = "991b3fb39c565003e35e29f49204834b06db31e48e2f821fb2c3a2699b65b36c"
SEALED_DIRECTORY = Path(".artifact-provenance-sealed")
BUILD_CODE = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from poetry.core.masonry.api import build_wheel; "
    "build_wheel(sys.argv[2], config_settings=None, metadata_directory=None)"
)


class CaptureError(Exception):
    pass


def require(ok, tag):
    if not ok:
        raise CaptureError(tag)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def command(argv, cwd, env, timeout=180, payload=None):
    """Never disclose child streams or exception messages to public Actions logs."""
    proc = subprocess.Popen(  # noqa: S603 -- all argv originate from fixed reviewed commands below; no shell
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(payload, timeout=timeout)
    except BaseException:
        for sig, wait in ((signal.SIGTERM, 3), (signal.SIGKILL, 5)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
            try:
                proc.communicate(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                continue
        raise CaptureError("bounded_command_failed_details_suppressed") from None
    require(len(stdout) + len(stderr) <= 4_000_000, "command_output_bound")
    require(proc.returncode == 0, "command_failed_details_suppressed")
    return stdout


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        super().__init__()
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(
            parsed.scheme == "https"
            and parsed.hostname in self.hosts
            and parsed.username is None
            and parsed.password is None,
            "download_redirect_refused",
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, expected, hosts, limit):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirect(hosts))
    with opener.open(url, timeout=60) as response:
        raw = response.read(limit + 1)
    require(len(raw) <= limit and sha(raw) == expected, "download_digest_refused")
    with destination.open("xb") as stream:
        stream.write(raw)
    return raw


def source_archive_extract(archive, destination):
    """Only this package subtree: no symlinks, hardlinks, special files or fixtures."""
    entries = []
    with tarfile.open(archive, "r:") as source:
        for item in source:
            path = Path(item.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in item.name, "source_archive_path")
            require(item.isdir() or item.isfile(), "source_archive_special_file")
            target = destination / path
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            require(item.size <= 5_000_000 and len(entries) < 2000, "source_archive_bound")
            target.parent.mkdir(parents=True, exist_ok=True)
            member = source.extractfile(item)
            require(member is not None, "source_archive_member")
            data = member.read(5_000_001)
            require(len(data) == item.size, "source_archive_size")
            with target.open("xb") as stream:
                stream.write(data)
            os.utime(target, (item.mtime, item.mtime))
            entries.append({"path": path.as_posix(), "sha256": sha(data), "mode": item.mode})
    return sorted(entries, key=lambda item: item["path"])


def backend_extract(wheel, destination):
    with zipfile.ZipFile(wheel) as archive:
        seen = set()
        for item in archive.infolist():
            path = Path(item.filename)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in item.filename
                and item.filename not in seen,
                "backend_archive_path",
            )
            seen.add(item.filename)
            require(
                not stat.S_ISLNK(item.external_attr >> 16) and item.file_size <= 5_000_000,
                "backend_archive_type_or_size",
            )
            target = destination / path
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(archive.read(item))


def prepare_age(work, env, recipient):
    archive = work / "age-v1.3.2-linux-amd64.tar.gz"
    download(
        AGE_URL,
        archive,
        AGE_ARCHIVE_SHA256,
        {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
        25_000_000,
    )
    with tarfile.open(archive, "r:gz") as source:
        members = [item for item in source.getmembers() if item.name == "age/age"]
        require(len(members) == 1 and members[0].isfile() and members[0].size <= 32_000_000, "age_binary_member")
        stream = source.extractfile(members[0])
        require(stream is not None, "age_binary_stream")
        raw = stream.read(32_000_001)
        require(len(raw) == members[0].size, "age_binary_size")
    executable = work / "age"
    executable.write_bytes(raw)
    executable.chmod(0o700)
    version = command([str(executable), "--version"], work, env).decode().strip()
    require(version.removeprefix("v") == AGE_VERSION, "age_version")
    # Validate the public recipient and v1 encryption capability before source fetch.
    probe = command([str(executable), "-r", recipient], work, env, payload=b"privacy-capability-probe")
    require(probe.startswith(b"age-encryption.org/v1\n"), "age_format")
    return executable, sha(raw), version


def capture(workspace, work, recipient, run_identity):
    env = {
        "HOME": str(work / "home"),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    (work / "home").mkdir()
    age, age_binary_sha, age_version = prepare_age(work, env, recipient)
    repo = work / "source-git"
    repo.mkdir()
    git = [
        "/usr/bin/git",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
    ]
    command([*git, "init", "--quiet"], repo, env)
    # Public exact HTTPS source needs no token. No persistent credential URL,
    # credential helper, Git config or interactive fallback is permitted.
    command([*git, "fetch", "--quiet", "--no-tags", "--depth=1", SOURCE_URL, SOURCE_COMMIT], repo, env, timeout=300)
    actual = command([*git, "rev-parse", "FETCH_HEAD"], repo, env).decode().strip()
    require(actual == SOURCE_COMMIT, "source_commit")
    tree = command([*git, "rev-parse", SOURCE_COMMIT + "^{tree}"], repo, env).decode().strip()
    subtree = command([*git, "rev-parse", SOURCE_COMMIT + ":" + SOURCE_SUBDIR], repo, env).decode().strip()
    source_tar = work / "app-sync-source.tar"
    source_tar.write_bytes(command([*git, "archive", "--format=tar", SOURCE_COMMIT + ":" + SOURCE_SUBDIR], repo, env))
    source = work / "app-sync-source"
    source.mkdir()
    files = source_archive_extract(source_tar, source)
    project = tomllib.loads((source / "pyproject.toml").read_text())
    require(
        project["build-system"] == {"requires": ["poetry-core"], "build-backend": "poetry.core.masonry.api"},
        "closed_build_backend",
    )
    metadata = project["tool"]["poetry"]
    require(
        metadata["name"] == "dotmac-app-sync" and metadata["version"] == "0.1.0a1" and "build" not in metadata,
        "fixed_package_no_build_script",
    )
    backend_wheel = work / BACKEND_FILENAME
    download(BACKEND_URL, backend_wheel, BACKEND_SHA256, {"files.pythonhosted.org"}, 1_000_000)
    backend = work / "backend"
    backend.mkdir()
    backend_extract(backend_wheel, backend)
    dist = work / "dist"
    dist.mkdir()
    build_command = [sys.executable, "-I", "-S", "-B", "-c", BUILD_CODE, str(backend), str(dist)]
    started = time.time()
    command(build_command, source, env, timeout=180)
    wheels = list(dist.iterdir())
    require(
        len(wheels) == 1
        and wheels[0].name == "dotmac_app_sync-0.1.0a1-py3-none-any.whl"
        and wheels[0].is_file()
        and not wheels[0].is_symlink(),
        "fixed_output_wheel",
    )
    wheel_sha = sha(wheels[0].read_bytes())
    provenance = {
        "schema": "AcademyAppSyncArtifactProvenance.v1",
        "consumer_candidate": ACADEMY_CANDIDATE,
        "consumer_tree": ACADEMY_TREE,
        "source_url": SOURCE_URL,
        "source_commit": actual,
        "source_tree": tree,
        "source_subdirectory": SOURCE_SUBDIR,
        "source_subtree": subtree,
        "source_files": files,
        "source_archive_sha256": sha(source_tar.read_bytes()),
        "source_mtime_policy": "Git archive metadata preserved; no SOURCE_DATE_EPOCH override or hash fitting",
        "backend": {
            "name": "poetry-core",
            "version": BACKEND_VERSION,
            "url": BACKEND_URL,
            "wheel_sha256": BACKEND_SHA256,
            "implicit_build_dependencies": False,
        },
        "interpreter": {
            "version": sys.version,
            "executable": sys.executable,
            "executable_sha256": sha(Path(sys.executable).read_bytes()),
        },
        "git_version": command([*git, "--version"], repo, env).decode().strip(),
        "build_command": build_command,
        "build_started_unix": started,
        "build_finished_unix": time.time(),
        "workflow_identity": run_identity,
        "wheel": {
            "filename": wheels[0].name,
            "sha256": wheel_sha,
            "staged_sha256": STAGED_WHEEL_SHA256,
            "staged_digest_equal": wheel_sha == STAGED_WHEEL_SHA256,
            "member_byte_parity_checked": False,
            "installed_byte_parity_checked": False,
        },
        "encryption": {
            "format": "age v1",
            "version": age_version,
            "archive_sha256": AGE_ARCHIVE_SHA256,
            "binary_sha256": age_binary_sha,
            "recipient_file_sha256": RECIPIENT_FILE_SHA256,
        },
        "publication_performed": False,
        "deployment_ready": False,
        "limits": [
            "A digest mismatch is evidence, not a reason to hide this artifact.",
            "No claim that a previously cached wheel was built by this CI run.",
            "Root must independently decrypt and compare member and installed bytes.",
        ],
    }
    provenance_file = work / "provenance.json"
    provenance_file.write_bytes(canonical(provenance) + b"\n")
    payload = work / "private-provenance.tar"
    with tarfile.open(payload, "w") as archive:
        for path in (wheels[0], backend_wheel, source_tar, provenance_file):
            archive.add(path, arcname=path.name, recursive=False)
    output = workspace / SEALED_DIRECTORY
    output.mkdir(mode=0o700)
    ciphertext = output / "app-sync-provenance.tar.age"
    command([str(age), "-r", recipient, "-o", str(ciphertext), str(payload)], work, env)
    require(ciphertext.read_bytes().startswith(b"age-encryption.org/v1\n"), "sealed_format")
    summary = {
        "schema": "AcademyEncryptedArtifactHashes.v1",
        "ciphertext_sha256": sha(ciphertext.read_bytes()),
        "recipient_file_sha256": RECIPIENT_FILE_SHA256,
        "provenance_sha256": sha(provenance_file.read_bytes()),
        "wheel_sha256": wheel_sha,
        "staged_wheel_sha256": STAGED_WHEEL_SHA256,
    }
    (output / "public-hashes.json").write_bytes(canonical(summary) + b"\n")
    return summary


def main():
    # Intentional source draft: no execution during preparation. Requires the
    # separately supplied public recipient; never accepts or reads a private key.
    try:
        require(
            os.environ.get("GITHUB_ACTIONS") == "true"
            and platform.system() == "Linux"
            and platform.machine() == "x86_64"
            and sys.version_info[:2] == (3, 12)
            and sys.flags.isolated
            and sys.flags.no_site,
            "hosted_python312_I_S_only",
        )
        require(
            os.environ.get("GITHUB_REPOSITORY") == "michaelayoade/dotmac_academy_app"
            and os.environ.get("GITHUB_REF") == "refs/heads/ops/a109-artifact-provenance-20261112",
            "fixed_workflow_branch",
        )
        workspace = Path.cwd().resolve()
        recipient_file = workspace / RECIPIENT_PATH
        require(recipient_file.is_file() and not recipient_file.is_symlink(), "public_recipient_required")
        raw = recipient_file.read_bytes()
        require(len(raw) <= 128 and sha(raw) == RECIPIENT_FILE_SHA256, "public_recipient_hash")
        recipient = raw.decode("ascii").strip()
        require(re.fullmatch(r"age1[0-9a-z]{58}", recipient) is not None, "single_age_public_recipient")
        require(not (workspace / SEALED_DIRECTORY).exists(), "fresh_sealed_output_required")
        run_identity = {
            key: os.environ.get(key)
            for key in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF")
        }
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="private-app-sync-provenance-") as temp:
            summary = capture(workspace, Path(temp), recipient, run_identity)
        print(canonical(summary).decode())  # Hash-only public output; never child streams or private package bytes.
        return 0
    except BaseException as exc:
        # Do not disclose paths, child errors, file contents or credentials.
        tag = str(exc) if isinstance(exc, CaptureError) else "unexpected_error_details_suppressed"
        print(json.dumps({"status": "failed", "refusal": tag}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
