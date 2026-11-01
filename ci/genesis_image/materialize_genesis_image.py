"""Pull the declared Genesis-only PostgreSQL image by digest and verify it before any test.

Run as ``/usr/bin/python3 -I ci/genesis_image/materialize_genesis_image.py`` (stdlib only)
from the checkout root. The only credential is the read-only ``FORGEJO_READ_TOKEN`` step
variable; it reaches ``docker login`` on stdin only, inside a private ``--config`` directory
that is logged out and deleted before the image is verified and before any test runs.
Nothing is tagged, pushed, loaded or saved. The image reference is exported to later steps
through GITHUB_ENV only after every check has passed. Any failure exits 1 with
``Genesis image materialization refused [P<n>]`` and never echoes subprocess output, the
token, or URLs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

REGISTRY = "registry.dotmac.io"
IDENTITY_URL = "https://" + REGISTRY + "/api/v1/user"
READER = "ci-reader"
DOCKER = "/usr/bin/docker"
DECLARATION = "ci/genesis_image/genesis-image-declaration.json"
REF_PATTERN = re.compile(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}")
DIGEST_PATTERN = re.compile(r"sha256:[a-f0-9]{64}")
TOKEN_PATTERN = re.compile(r"[\x21-\x7e]{8,512}")
KEYS = frozenset(
    {
        "genesis_image_reference",
        "platform",
        "manifest_digest",
        "manifest_media_type",
        "manifest_bytes",
        "config_digest",
        "layer_count",
        "layer_blob_digest",
        "layer_blob_bytes",
        "layer_diff_id",
        "payload",
        "unstripped_sha256",
        "base",
        "server_version_num",
        "collation_version",
        "archive",
        "source",
        "owner_source",
        "retained_schema_sha256",
        "evidence",
        "documented_corrections",
        "claim",
        "derived_runtime_image_digest",
        "admission_digest",
        "FRESH_CANONICAL_SHA256",
        "name_note",
    }
)
SOURCE_KEYS = frozenset(
    {
        "kind",
        "registry",
        "repository",
        "tag",
        "pull_identity",
        "pull_secret_name",
        "push_identity",
        "push_receipt_sha256",
        "archive_note",
    }
)

Runner = Callable[..., tuple[int, bytes]]
Opener = Callable[..., Any]


class Refused(Exception):
    def __init__(self, step: int) -> None:
        super().__init__(step)
        self.step = step


def need(condition: object, step: int) -> None:
    if not condition:
        raise Refused(step)


def run_command(argv: list[str], *, stdin: bytes | None = None, env: Mapping[str, str]) -> tuple[int, bytes]:
    """Run one fixed docker command; output is returned to the caller and never printed."""
    try:
        result = subprocess.run(  # noqa: S603 -- fixed absolute docker path, list argv, no shell
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(env),
            check=False,
            timeout=900,
        )
    except (OSError, subprocess.SubprocessError):
        return 255, b""
    return result.returncode, result.stdout


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def default_urlopen(request: urllib.request.Request, timeout: int) -> Any:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    return opener.open(request, timeout=timeout)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_image(run: Runner, env: Mapping[str, str], reference: str, step: int) -> dict[str, Any]:
    code, output = run([DOCKER, "image", "inspect", reference], env=env)
    need(code == 0, step)
    try:
        parsed = json.loads(output)
    except ValueError:
        raise Refused(step) from None
    need(isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict), step)
    return parsed[0]


def load_declaration(root: Path) -> dict[str, Any]:
    try:
        declared = json.loads((root / DECLARATION).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Refused(1) from None
    need(type(declared) is dict and set(declared) == KEYS, 1)
    reference = declared["genesis_image_reference"]
    source = declared["source"]
    need(type(source) is dict and set(source) == SOURCE_KEYS, 1)
    need(source["registry"] == REGISTRY and source["pull_identity"] == READER, 1)
    need(source["pull_secret_name"] == "FORGEJO_READ_TOKEN", 1)  # noqa: S105 -- a secret NAME, not a value
    need(type(source["repository"]) is str and type(source["tag"]) is str, 1)
    need(type(reference) is str and REF_PATTERN.fullmatch(reference) is not None, 1)
    need(reference == REGISTRY + "/" + source["repository"] + "@" + declared["manifest_digest"], 1)
    for field in ("manifest_digest", "config_digest", "layer_blob_digest", "layer_diff_id"):
        need(type(declared[field]) is str and DIGEST_PATTERN.fullmatch(declared[field]) is not None, 1)
    need(source["tag"] == "c58-" + declared["manifest_digest"][7:19], 1)
    need(declared["platform"] == "linux/amd64", 1)
    for field in ("derived_runtime_image_digest", "admission_digest", "FRESH_CANONICAL_SHA256"):
        need(declared[field] is None, 1)
    receipt = source["push_receipt_sha256"]
    need(type(receipt) is str and re.fullmatch(r"[a-f0-9]{64}", receipt) is not None, 1)
    base = declared["base"]
    need(type(base) is dict and type(base.get("reference")) is str and type(base.get("layer_count")) is int, 1)
    need(type(declared["layer_count"]) is int and declared["layer_count"] == base["layer_count"] + 1, 1)
    return declared


def check_registry_scope(urlopen: Opener, token: str, repository: str) -> None:
    """Exchange the token for a registry JWT and refuse unless its scope is read-only with read:package.

    Only the base64url payload is decoded (signature not verified); nothing is printed.
    """
    basic = "Basic " + base64.b64encode((READER + ":" + token).encode("ascii")).decode("ascii")
    url = f"https://{REGISTRY}/v2/token?service=container_registry&scope=repository:{repository}:pull"
    request = urllib.request.Request(url, headers={"Authorization": basic}, method="GET")  # noqa: S310 -- fixed https URL
    try:
        response = urlopen(request, 30)
    except (urllib.error.URLError, OSError, ValueError):
        raise Refused(4) from None
    try:
        need(response.status == 200, 4)
        value = json.loads(response.read(1 << 16)).get("token")
        need(isinstance(value, str), 4)
        parts = value.split(".")
        need(len(parts) == 3, 4)
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, AttributeError, TypeError):
        raise Refused(4) from None
    finally:
        response.close()
    need(isinstance(claims, dict), 4)
    user_id, scope = claims.get("UserID"), claims.get("Scope")
    need(type(user_id) is int and user_id > 0 and isinstance(scope, str) and scope.strip(), 4)
    scopes = [item for item in re.split(r"[,\s]+", scope) if item]
    need("read:package" in scopes, 4)
    need(all(re.fullmatch(r"read:[a-z-]+|public-only", item) for item in scopes), 4)


def check_identity(urlopen: Opener, token: str) -> str:
    """Non-mutating identity check. Returns 'verified' or 'unverifiable'; only status is used."""
    request = urllib.request.Request(  # noqa: S310 -- fixed https URL
        IDENTITY_URL, headers={"Authorization": "token " + token, "Accept": "application/json"}, method="GET"
    )
    try:
        response = urlopen(request, 30)
    except urllib.error.HTTPError as error:
        need(error.code == 403, 4)
        return "unverifiable"
    except (urllib.error.URLError, OSError, ValueError):
        raise Refused(4) from None
    try:
        need(response.status == 200, 4)
        login = json.loads(response.read(1 << 16)).get("login")
    except (ValueError, AttributeError):
        raise Refused(4) from None
    finally:
        response.close()
    need(login == READER, 4)
    return "verified"


def materialize(
    environ: Mapping[str, str],
    root: Path,
    *,
    run: Runner = run_command,
    urlopen: Opener = default_urlopen,
) -> str:
    # P0: environment
    need(environ.get("CI") == "true" and environ.get("GITHUB_ACTIONS") == "true", 0)
    need("ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE" not in environ, 0)
    need(not any(name in environ for name in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT")), 0)
    runner_temp = environ.get("RUNNER_TEMP", "")
    github_env = environ.get("GITHUB_ENV", "")
    home = environ.get("HOME", "")
    need(os.path.isabs(runner_temp) and os.path.isdir(runner_temp), 0)
    need(os.path.isabs(home), 0)
    need(os.path.isabs(github_env) and os.path.isfile(github_env) and not os.path.islink(github_env), 0)
    token = environ.get("FORGEJO_READ_TOKEN", "")
    need(TOKEN_PATTERN.fullmatch(token) is not None, 0)
    child_env = {"PATH": "/usr/bin:/bin", "HOME": home}

    # P1: declaration
    declared = load_declaration(root)
    reference: str = declared["genesis_image_reference"]
    base = declared["base"]
    source_repository: str = declared["source"]["repository"]

    # P2: frozen source pins
    try:
        owner = sha256_file(root / declared["owner_source"]["path"])
        schema = sha256_file(root / "app/maintenance/retained_schema.py")
    except (OSError, KeyError, TypeError):
        raise Refused(2) from None
    need(owner == declared["owner_source"]["sha256"], 2)
    need(schema == declared["retained_schema_sha256"], 2)

    # P3: the ordinary service stays the derived image's official base
    need(environ.get("ACADEMY_ORDINARY_SERVICE_IMAGE") == base["reference"], 3)
    need(environ.get("ACADEMY_RETAINED_EXPECTED_SERVER_VERSION_NUM") == str(declared["server_version_num"]), 3)
    try:
        collation = json.loads(environ.get("ACADEMY_RETAINED_EXPECTED_COLLATION_VERSION", ""))
    except ValueError:
        raise Refused(3) from None
    need(collation == declared["collation_version"], 3)

    # P4: identity (non-mutating)
    check_registry_scope(urlopen, token, source_repository)
    identity = check_identity(urlopen, token)  # a 403 continues only because the scope check above passed

    # P5: base image present and exact
    base_image = inspect_image(run, child_env, base["reference"], 5)
    base_layers = base_image.get("RootFS", {}).get("Layers")
    need(base_image.get("Id") == base["config"], 5)
    need(isinstance(base_layers, list) and len(base_layers) == base["layer_count"], 5)

    # P6-P8: login, pull by digest, always log out and delete the private config
    config = Path(runner_temp) / "genesis-docker-config"
    need(not os.path.lexists(config), 6)
    try:
        os.mkdir(config, 0o700)
        os.chmod(config, 0o700)
    except OSError:
        raise Refused(6) from None
    failure: Refused | None = None
    try:
        login_code, _ = run(
            [DOCKER, "--config", str(config), "login", REGISTRY, "-u", READER, "--password-stdin"],
            stdin=(token + "\n").encode("ascii"),
            env=child_env,
        )
        need(login_code == 0, 6)
        pull_code, _ = run(
            [DOCKER, "--config", str(config), "pull", "--platform", declared["platform"], reference], env=child_env
        )
        need(pull_code == 0, 7)
    except Refused as refusal:
        failure = refusal
    finally:
        run([DOCKER, "--config", str(config), "logout", REGISTRY], env=child_env)
        shutil.rmtree(config, ignore_errors=True)
        removed = not os.path.lexists(config)
    need(removed, 8)
    if failure is not None:
        raise failure

    # P9: verify the pulled image
    image = inspect_image(run, child_env, reference, 9)
    layers = image.get("RootFS", {}).get("Layers")
    need(image.get("Id") == declared["config_digest"], 9)
    need(reference in (image.get("RepoDigests") or []), 9)
    need(layers == [*base_layers, declared["layer_diff_id"]], 9)
    need(image.get("Os") == "linux" and image.get("Architecture") == "amd64", 9)

    # P10: export only after every check passed
    try:
        descriptor = os.open(github_env, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write("ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE=" + reference + "\n")
    except OSError:
        raise Refused(10) from None
    print("ACADEMY_GENESIS_IMAGE MATERIALIZED " + reference + " identity=" + identity)
    return reference


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    try:
        materialize(os.environ, root)
    except Refused as refusal:
        print(f"Genesis image materialization refused [P{refusal.step}]", file=sys.stderr)
        return 1
    except Exception:
        print("Genesis image materialization refused [P?]", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
