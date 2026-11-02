"""Static contract for the Genesis-only PostgreSQL image declaration (C59).

Pure: no Docker, network or database. Docker and the registry identity call are
fakes injected into the loader. The independent copy of every pinned value below
is deliberately typed out again, so the declaration cannot drift with its test.
"""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import importlib.util
import json
import re
import shutil
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DECLARATION = ROOT / "ci/genesis_image/genesis-image-declaration.json"
LOADER = ROOT / "ci/genesis_image/materialize_genesis_image.py"
WORKFLOW = ROOT / ".github/workflows/ci.yml"

MANIFEST = "sha256:25612bfc5ff99fc919021b43a3a9f3fac0b3a6bccc675b47940735bdd4780325"
REF = "registry.dotmac.io/dotmac/academy-genesis-pg16@" + MANIFEST
CONFIG = "sha256:a64e9541d797c3d151dd6a148e4bab9729c7ae66e6e3d9abff559a11c9f6a031"
DIFF_ID = "sha256:20561fc8eb54ba00ac5862c9cc57a31aefb0ae923cd450de0bceec9a869bf0e9"
BASE_REF = "postgres@sha256:b95b87e93ceb7594715d5c71fb6e09f6fc878851ab537735d617325eb9ba8b1b"
BASE_CONFIG = "sha256:74d436cb49d3398cf7b5d7b33635d43623d9e4da4b93c22db453f7d5d81181b1"
PENDING = "PENDING_PUSH_RECEIPT_SHA256"
PUSH_RECEIPT_SHA256 = "d89f6058ec7eae5c2005b1625c2a2b973c3975fd2ca99865eb6bf646993b7ab4"  # C59 push receipt, pushed_and_verified 2026-11-01
RECEIPT = "e" * 64
TOKEN = "fake-forgejo-token-0123456789abcdef"

EXPECTED = {
    "genesis_image_reference": REF,
    "platform": "linux/amd64",
    "manifest_digest": MANIFEST,
    "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
    "manifest_bytes": 2595,
    "config_digest": CONFIG,
    "layer_count": 15,
    "layer_blob_digest": "sha256:fd70beb9c4c9d0c1865c59c715802a6c1a11501fdd46364cd0d7708e810190f1",
    "layer_blob_bytes": 4122683,
    "layer_diff_id": DIFF_ID,
    "payload": {
        "path": "/usr/lib/postgresql/16/bin/postgres",
        "sha256": "f7666d9e4cf06aca25c2567a61528879e2446a2494288d6005512c2866bf6033",
        "bytes": 9700096,
    },
    "unstripped_sha256": "9d7dd8d5d61a8ed0d91919966488746646c9d57efed6b37c57f8149ef58c7e06",
    "base": {
        "reference": BASE_REF,
        "config": BASE_CONFIG,
        "layer_count": 14,
        "base_binary_sha256": "ea528a9f858bce5eef557522820c945a3d3b9fd260a15d6d0313d6350574229d",
    },
    "server_version_num": 160015,
    "collation_version": "2.41",
    "archive": {
        "name": "academy-genesis-postgres16-oci.tar",
        "sha256": "447beb9c807aab57b13e9ab195abf76683c12cbd31427d798e58744b4466b60c",
        "bytes": 164454400,
    },
    "owner_source": {
        "path": "app/maintenance/retained_hosted_genesis.py",
        "git_blob": "4ae285992ecbcd90c3d6438e501baab19f35cfc2",
        "sha256": "f6a385c14a27a791ad6891c7ea8e87eef9c53871ac51d6160289dc05cb525810",
    },
    "retained_schema_sha256": "6b4f800bb76f761996cc0cc5b6325f375fa5b10e9c2e997aaaa59a01dc93bc84",
    "evidence": {
        "c58": {
            "run_id": 41217897635,
            "run_attempt": 1,
            "commit": "89cc2d2ac5cf0a7fa6be1959e43c9d5e6ec3b511",
            "artifacts": {
                "a": {
                    "id": 13049160463,
                    "digest": "sha256:a61a949b406650898f74c4e7ae25882341f71467b4608cd618b66a7f0cb22a46",
                },
                "b": {
                    "id": 13049285069,
                    "digest": "sha256:efc86611f2993ce9f748f03b20da795699f5bade8437ef9ddef7f6b6857b1e25",
                },
                "compare": {
                    "id": 13048883551,
                    "digest": "sha256:d2408a2872b8be423a0974c806c59d88695e7d1e17ee478c4b1231edd0e2f7f6",
                },
                "canary": {
                    "id": 13049241947,
                    "digest": "sha256:02c1f76e70104e95624222afe9c34eade685d3257f16abfc3f6aa803dd00c092",
                },
            },
            "receipt_sha256": {
                "build_a": "61935614b08f6ce1c0627f548a7d31bee01e6642df2dbbdc3d84a9dd7b99d9d6",
                "build_b": "1cb2b6630351d18660c8d26656ce8fafb5fd0d293f42d58c1c032ff53772b9b8",
                "compare": "7f61d96d48ad87c908ea73ba00f3f3382805ad422a43ec7090aadc5ff7cdf21b",
                "canary": "8ad4bdcebaefd7ce76d50984654e17aca56046f68b1970c0d44a5f848170ae7b",
            },
        },
        "c56": {
            "run_id": 41021359997,
            "receipt_sha256": "3860f12423e20778d3b3fbdc1c32803661acc2e3386795881d3c7888eda76e3b",
        },
        "s1_review_sha256": "8952fb1aed96cbc8709db15d7dd6ac8b4a1b2bd832f88da82d7008c9dbc0799f",
        "s6_review_sha256": "1fd8720ecf6038859776c423bbeada4ba02d9f833287b5e9f721117f716ab738",
        "patch": {
            "diff_sha256": "9c9a6e7cd9e85777b8186cf2ba99adde166e89dd92090f3db0add830a7f5b4c9",
            "patched_miscinit_sha256": "354d87983b76c7e7cb6c67d877a18e4058c8700ef358cf66694610e0921dfa87",
        },
    },
    "derived_runtime_image_digest": None,
    "admission_digest": None,
    "FRESH_CANONICAL_SHA256": None,
}
EXPECTED_SOURCE = {
    "kind": "oci_distribution_registry",
    "registry": "registry.dotmac.io",
    "repository": "dotmac/academy-genesis-pg16",
    "tag": "c58-25612bfc5ff9",
    "pull_identity": "ci-reader",
    "pull_secret_name": "FORGEJO_READ_TOKEN",
    "push_identity": "ci-publisher (one-time, workstation, by Michael)",
}
FREE_TEXT_KEYS = {"documented_corrections", "claim", "name_note"}

MUST_NOT_CHANGE = {
    ".github/workflows/genesis-postgres-derived-build.yml": "d2c7567a4d681008b5ccfff14206d2a69d4f570374920567808656da52a9b288",
    "ci/postgres_genesis_derived/derived-build-lock.json": "ce29340304b18e2fe0ed01f8a8827b07ed4f4caf6ea56c31db6cf3ac8105c34b",
    "ci/postgres_genesis_derived/recheck-o-rdonly.diff": "9c9a6e7cd9e85777b8186cf2ba99adde166e89dd92090f3db0add830a7f5b4c9",
    "ci/postgres_genesis_derived/academy-backend.mk": "8ecb292e61b76c8aa3e97874814d2da95e574d0b49907ca8886de44011253ab2",
    "ci/postgres_genesis_derived/build_derived.py": "01bb529863b2469864418c03d3b22ff61a60c5991ccdc96e59fd1c5b520e953c",
    "ci/postgres_genesis_derived/in_builder_build.py": "e88e560ffde89827aa4c59cd1ca263c7bf9d46e12025d3a1ea235b108e5686d6",
    "ci/postgres_genesis_derived/assemble_oci.py": "e493d5e3fdb075cb7e3238b00cef3ef20b20811cb5bc5844d4fb9eaf14f73c43",
    "ci/postgres_genesis_derived/compare_ab.py": "cdc4aeb51a77d514c4682b5d95f4b992cf49d6c21c1d4f0cc26c41c65ed09cd6",
    "ci/postgres_genesis_derived/static_registry.py": "8c8971b9cec8166260f86c647f890da090056e78aa51fd9ab70a34e895b295d1",
    "ci/postgres_genesis_derived/canaries.py": "4f8cb31048390f03015f35844782bb6d33803eee98f7bda9bbe7529031a10094",
    "ci/postgres_genesis_derived/canaries-requirements.txt": "b21cccf992c348efea2f84b4e3fc5166663df9518cef8862cc7b5b726148de4f",
    "tests/test_genesis_derived_static.py": "ace114c9f51cde354ed5d63b60726d77dc31e635f549f8530de19d813680bf6f",
    "ci/postgres_genesis/source-candidate.json": "efc9cc1deaa17c3f68bf2e92a56ab9e5fdcdbbdc45264afb12f6b956cf5d5cc2",
    "tests/ci_skip_allowlist.txt": "3ba7d383c7fea64ef1df0c8484a59eeae1c81bc640517686e80876241a44abda",
    "scripts/declare_retained_hosted_bindings.py": "47b9f74bc5495da19318d715e6e854b230bbae7c187aa3c8eace9176f2037a22",
    "tests/fixtures/hosted_genesis.py": "d323563e7aa93e3f7271a2bbb86083746cacec440bf78041793396058387787c",
    "app/maintenance/fresh_product.py": "249e2222ccf39f92255155b1316e50812cb847e877c5ab975c84cd633b546d62",
    "app/maintenance/retained_hosted_genesis.py": "f6a385c14a27a791ad6891c7ea8e87eef9c53871ac51d6160289dc05cb525810",
    "app/maintenance/retained_schema.py": "6b4f800bb76f761996cc0cc5b6325f375fa5b10e9c2e997aaaa59a01dc93bc84",
}
# C60: the reviewed hosted H == F digest (CI 41383205433 on c49ffae).
FRESH_CANONICAL_PIN = "f434069763f341055bbd670a6042339c8550c3df6959d74c3757014ef6af002b"
MATERIALIZE_NAME = "Materialize the declared Genesis-only PostgreSQL image"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_declaration() -> dict[str, Any]:
    return json.loads(DECLARATION.read_text(encoding="utf-8"))


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("materialize_genesis_image_under_test", LOADER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loader = _load_module()


# --------------------------------------------------------------- declaration


def test_declaration_equals_independent_pins_and_exact_key_set():
    declared = _load_declaration()
    source = declared.pop("source")
    for key in FREE_TEXT_KEYS:
        assert isinstance(declared.pop(key), (str, list))
    assert declared == EXPECTED
    receipt = source.pop("push_receipt_sha256")
    assert receipt == PUSH_RECEIPT_SHA256
    source.pop("archive_note")
    assert source == EXPECTED_SOURCE


def test_reference_is_registry_name_at_manifest_and_matches_every_consumer_regex():
    declared = _load_declaration()
    reference = declared["genesis_image_reference"]
    assert reference == "registry.dotmac.io/dotmac/academy-genesis-pg16@" + declared["manifest_digest"]
    assert "localhost/" not in reference
    assert re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", reference)  # owner and declare script
    assert re.fullmatch(r"[A-Za-z0-9_./:@-]{1,240}", reference)  # retained_environment
    assert declared["source"]["tag"] == "c58-" + declared["manifest_digest"].split(":")[1][:12]
    text = LOADER.read_text(encoding="utf-8") + WORKFLOW.read_text(encoding="utf-8")
    assert "gh release" not in text and "gh api" not in text


def test_admission_runtime_and_fresh_values_stay_null():
    declared = _load_declaration()
    for key in ("derived_runtime_image_digest", "admission_digest", "FRESH_CANONICAL_SHA256"):
        assert declared[key] is None
    tree = ast.parse((ROOT / "app/maintenance/fresh_product.py").read_text(encoding="utf-8"))
    values = [
        node.value
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "FRESH_CANONICAL_SHA256"
    ]
    assert len(values) == 1 and isinstance(values[0], ast.Constant) and values[0].value == FRESH_CANONICAL_PIN

    def nulls(node: Any) -> list[Any]:
        found: list[Any] = []
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("derived_runtime_image_digest", "admission_digest", "FRESH_CANONICAL_SHA256"):
                    found.append(value)
                found += nulls(value)
        elif isinstance(node, list):
            for value in node:
                found += nulls(value)
        return found

    for name in ("ci/postgres_genesis_derived/derived-build-lock.json", "ci/postgres_genesis/source-candidate.json"):
        assert all(value is None for value in nulls(json.loads((ROOT / name).read_text(encoding="utf-8"))))


@pytest.mark.parametrize(("name", "digest"), sorted(MUST_NOT_CHANGE.items()))
def test_protected_files_keep_their_pinned_hashes(name, digest):
    assert _sha256(ROOT / name) == digest


def test_pinned_push_receipt_loads():
    assert _load_declaration()["source"]["push_receipt_sha256"] == PUSH_RECEIPT_SHA256
    loader.load_declaration(ROOT)


# ------------------------------------------------------------------ workflow


@pytest.fixture
def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_workflow_permissions_service_and_materialize_step(workflow):
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["test"]
    assert job["services"]["db"]["image"] == "${{ vars.ACADEMY_RETAINED_PG_IMAGE }}"
    for service in job["services"].values():
        assert "academy-genesis" not in service["image"] and "localhost/" not in service["image"]
    assert "ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE" not in job["env"]
    assert "DOCKER_CONFIG" not in job["env"]
    steps = job["steps"]
    for step in steps:
        assert "ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE" not in step.get("env", {})
        assert "DOCKER_CONFIG" not in step.get("env", {})
    matching = [i for i, step in enumerate(steps) if step.get("name") == MATERIALIZE_NAME]
    assert len(matching) == 1
    position = matching[0]
    assert steps[position - 1]["uses"].startswith("actions/checkout@")
    names = [step.get("name") for step in steps]
    assert position < names.index("Declare hosted environment expectations before profile observation")
    assert position < names.index("Discover historical and fresh schema convergence without commit")
    step = steps[position]
    assert set(step) == {"name", "env", "run"}  # no if, no continue-on-error
    assert step["env"] == {
        "FORGEJO_READ_TOKEN": "${{ secrets.FORGEJO_READ_TOKEN }}",
        "ACADEMY_ORDINARY_SERVICE_IMAGE": "${{ vars.ACADEMY_RETAINED_PG_IMAGE }}",
    }
    assert step["run"] == "/usr/bin/python3 -I ci/genesis_image/materialize_genesis_image.py"
    carriers = [i for i, s in enumerate(steps) if "secrets.FORGEJO_READ_TOKEN" in json.dumps(s)]
    assert carriers == [position]


# -------------------------------------------------------------------- loader


class FakeDocker:
    def __init__(self, config_dir: Path) -> None:
        self.calls: list[dict[str, Any]] = []
        self.config_dir = config_dir
        self.login_code = 0
        self.pull_code = 0
        self.base_id = BASE_CONFIG
        self.base_layers = [f"sha256:{i:064x}" for i in range(14)]
        self.image_id = CONFIG
        self.base_descriptor: Any = None  # None: classic store (no Descriptor key)
        self.base_descriptor_null = False  # True: emit an explicit "Descriptor": null
        self.base_os = "linux"
        self.base_arch = "amd64"
        self.image_descriptor: Any = None
        self.repo_digests = [REF]
        self.image_layers: list[str] | None = None
        self.os = "linux"
        self.arch = "amd64"
        self.seen_config_dir = False

    def __call__(self, argv, *, stdin=None, env):
        self.calls.append({"argv": list(argv), "stdin": stdin, "env": dict(env)})
        verb = argv[1:]
        if verb[0] == "--config":
            self.seen_config_dir = self.seen_config_dir or self.config_dir.is_dir()
            if verb[2] == "login":
                return self.login_code, b"login output must never be echoed"
            if verb[2] == "pull":
                return self.pull_code, b"pull output must never be echoed"
            if verb[2] == "logout":
                return 0, b""
        if verb[:2] == ["image", "inspect"]:
            if verb[2] == BASE_REF:
                base: dict[str, Any] = {
                    "Id": self.base_id,
                    "RootFS": {"Layers": self.base_layers},
                    "Os": self.base_os,
                    "Architecture": self.base_arch,
                }
                if self.base_descriptor_null:
                    base["Descriptor"] = None
                if self.base_descriptor is not None:
                    base["Descriptor"] = self.base_descriptor
                return 0, json.dumps([base]).encode()
            assert verb[2] == REF
            layers = self.image_layers if self.image_layers is not None else [*self.base_layers, DIFF_ID]
            image: dict[str, Any] = {
                "Id": self.image_id,
                "RepoDigests": self.repo_digests,
                "RootFS": {"Layers": layers},
                "Os": self.os,
                "Architecture": self.arch,
            }
            if self.image_descriptor is not None:
                image["Descriptor"] = self.image_descriptor
            return 0, json.dumps([image]).encode()
        raise AssertionError(argv)


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, _limit: int = -1) -> bytes:
        return self._body

    def close(self) -> None:
        return None


def _jwt(claims: dict[str, Any]) -> str:
    def part(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    return ".".join([part(b'{"alg":"none"}'), part(json.dumps(claims).encode()), "c2ln"])


class FakeIdentity:
    def __init__(self) -> None:
        self.status = 200
        self.login = "ci-reader"
        self.requests: list[Any] = []
        self.claims: dict[str, Any] | None = {"UserID": 7, "Scope": "read:package"}
        self.raw_token: str | None = None
        self.token_status = 200

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if "/v2/token" in request.full_url:
            if self.token_status != 200:
                raise urllib.error.HTTPError(request.full_url, self.token_status, "x", {}, None)  # type: ignore[arg-type]
            token = self.raw_token if self.raw_token is not None else _jwt(self.claims or {})
            return FakeResponse(200, json.dumps({"token": token}).encode())
        if self.status == 200:
            return FakeResponse(200, json.dumps({"login": self.login}).encode())
        raise urllib.error.HTTPError(request.full_url, self.status, "x", {}, None)  # type: ignore[arg-type]


@pytest.fixture
def world(tmp_path):
    root = tmp_path / "checkout"
    for relative in ("app/maintenance/retained_hosted_genesis.py", "app/maintenance/retained_schema.py"):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, root / relative)
    declared = _load_declaration()
    declared["source"]["push_receipt_sha256"] = RECEIPT
    (root / "ci/genesis_image").mkdir(parents=True)
    (root / "ci/genesis_image/genesis-image-declaration.json").write_text(json.dumps(declared))
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    github_env = tmp_path / "github_env"
    github_env.write_text("")
    environ = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_ENV": str(github_env),
        "HOME": str(tmp_path),
        "FORGEJO_READ_TOKEN": TOKEN,
        "ACADEMY_ORDINARY_SERVICE_IMAGE": BASE_REF,
        "ACADEMY_RETAINED_EXPECTED_SERVER_VERSION_NUM": "160015",
        "ACADEMY_RETAINED_EXPECTED_COLLATION_VERSION": '"2.41"',
    }
    return {
        "root": root,
        "environ": environ,
        "docker": FakeDocker(runner_temp / "genesis-docker-config"),
        "identity": FakeIdentity(),
        "config": runner_temp / "genesis-docker-config",
        "github_env": github_env,
    }


def _go(world):
    return loader.materialize(world["environ"], world["root"], run=world["docker"], urlopen=world["identity"])


def test_happy_path_exports_one_line_and_confines_the_token_to_login_stdin(world, capsys):
    assert _go(world) == REF
    assert world["github_env"].read_text() == "ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE=" + REF + "\n"
    printed = capsys.readouterr()
    assert printed.out == "ACADEMY_GENESIS_IMAGE MATERIALIZED " + REF + " identity=verified\n"
    assert TOKEN not in printed.out + printed.err and "must never be echoed" not in printed.out + printed.err
    calls = world["docker"].calls
    carriers = [c for c in calls if c["stdin"] is not None]
    assert len(carriers) == 1 and carriers[0]["stdin"] == (TOKEN + "\n").encode()
    assert carriers[0]["argv"][1:3] == ["--config", str(world["config"])] and "login" in carriers[0]["argv"]
    for call in calls:
        assert TOKEN not in " ".join(call["argv"]) + json.dumps(call["env"])
        assert set(call["env"]) == {"PATH", "HOME"}
        assert call["argv"][0] == "/usr/bin/docker"
        assert not {"tag", "push", "load", "save", "build", "run"} & set(call["argv"])
    scoped = [c["argv"] for c in calls if "--config" in c["argv"]]
    assert [a[3] for a in scoped] == ["login", "pull", "logout"]
    assert all(a[2] == str(world["config"]) for a in scoped)
    pull = next(a for a in scoped if a[3] == "pull")
    assert pull[-1] == REF and "@sha256:" in pull[-1] and pull[4:6] == ["--platform", "linux/amd64"]
    assert world["docker"].seen_config_dir and not world["config"].exists()
    scope_request, identity_request = (r[0] for r in world["identity"].requests)
    assert scope_request.full_url.startswith("https://registry.dotmac.io/v2/token?")
    assert (
        identity_request.full_url == "https://registry.dotmac.io/api/v1/user" and identity_request.get_method() == "GET"
    )
    assert next(c["argv"][3] for c in calls if "--config" in c["argv"]) == "login"  # scope checked before this


def test_containerd_image_store_pins_manifest_digests_and_exports(world, capsys):
    _containerd(world)
    assert _go(world) == REF
    assert world["github_env"].read_text() == "ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE=" + REF + "\n"
    assert capsys.readouterr().out == "ACADEMY_GENESIS_IMAGE MATERIALIZED " + REF + " identity=verified\n"


def test_refusal_detail_names_only_public_digests(world, capsys):
    _containerd(world, base_id=BASE_CONFIG)
    with pytest.raises(loader.Refused) as refused:
        _go(world)
    assert refused.value.detail == f"id={BASE_CONFIG} descriptor={BASE_REF.rpartition('@')[2]} store=containerd"


def test_identity_403_continues_as_unverifiable_when_scope_is_read_only(world, capsys):
    world["identity"].status = 403
    world["identity"].claims = {"UserID": 7, "Scope": "read:package,read:user"}
    _go(world)
    assert capsys.readouterr().out.endswith("identity=unverifiable\n")
    assert world["github_env"].read_text().count("\n") == 1


def _env(name, value=None):
    def mutate(world):
        if value is None:
            world["environ"].pop(name, None)
        else:
            world["environ"][name] = value

    return mutate


def _drift(relative):
    def mutate(world):
        with open(world["root"] / relative, "ab") as handle:
            handle.write(b"# drift\n")

    return mutate


def _declaration(edit):
    def mutate(world):
        path = world["root"] / "ci/genesis_image/genesis-image-declaration.json"
        declared = json.loads(path.read_text())
        edit(declared)
        path.write_text(json.dumps(declared))

    return mutate


def _containerd(world, *, base_id=None, base_digest=None, image_id=None, image_digest=None):
    """Docker 29 containerd image store: Id and Descriptor.digest are the pinned manifest/index digest."""
    docker = world["docker"]
    base_pin = BASE_REF.rpartition("@")[2]
    image_pin = REF.rpartition("@")[2]
    docker.base_id = base_id or base_pin
    docker.base_descriptor = {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": base_digest or base_pin}
    docker.image_id = image_id or image_pin
    docker.image_descriptor = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": image_digest or image_pin,
    }


def _attr(name, value):
    def mutate(world):
        setattr(world["docker"], name, value)

    return mutate


def _claims(value):
    def mutate(world):
        world["identity"].claims = value

    return mutate


def _raw_token(value):
    def mutate(world):
        world["identity"].raw_token = value

    return mutate


def _token_status(value):
    def mutate(world):
        world["identity"].token_status = value

    return mutate


def _identity(status, login="ci-reader"):
    def mutate(world):
        world["identity"].status = status
        world["identity"].login = login

    return mutate


CASES = [
    ("empty_token", _env("FORGEJO_READ_TOKEN", ""), 0),
    ("missing_token", _env("FORGEJO_READ_TOKEN"), 0),
    ("whitespace_token", _env("FORGEJO_READ_TOKEN", "has space in it 123"), 0),
    ("preset_image", _env("ACADEMY_RETAINED_EXPECTED_SERVICE_IMAGE", REF), 0),
    ("docker_config", _env("DOCKER_CONFIG", "/tmp/x"), 0),
    ("docker_host", _env("DOCKER_HOST", "tcp://127.0.0.1:1"), 0),
    ("docker_context", _env("DOCKER_CONTEXT", "x"), 0),
    ("not_ci", _env("CI", "false"), 0),
    ("relative_runner_temp", _env("RUNNER_TEMP", "relative"), 0),
    ("placeholder_receipt", _declaration(lambda d: d["source"].update(push_receipt_sha256=PENDING)), 1),
    ("admission_set", _declaration(lambda d: d.update(admission_digest=MANIFEST)), 1),
    ("reference_not_manifest", _declaration(lambda d: d.update(genesis_image_reference=REF[:-1] + "0")), 1),
    ("extra_key", _declaration(lambda d: d.update(extra=1)), 1),
    ("owner_drift", _drift("app/maintenance/retained_hosted_genesis.py"), 2),
    ("schema_drift", _drift("app/maintenance/retained_schema.py"), 2),
    ("wrong_service_var", _env("ACADEMY_ORDINARY_SERVICE_IMAGE", "postgres@sha256:" + "0" * 64), 3),
    ("wrong_version", _env("ACADEMY_RETAINED_EXPECTED_SERVER_VERSION_NUM", "160016"), 3),
    ("wrong_collation", _env("ACADEMY_RETAINED_EXPECTED_COLLATION_VERSION", '"2.40"'), 3),
    ("identity_other_login", _identity(200, "someone-else"), 4),
    ("identity_401", _identity(401), 4),
    ("identity_500", _identity(500), 4),
    ("identity_redirect", _identity(302), 4),
    ("scope_all", _claims({"UserID": 7, "Scope": "all"}), 4),
    ("scope_write_package", _claims({"UserID": 7, "Scope": "read:package,write:package"}), 4),
    ("scope_write_other", _claims({"UserID": 7, "Scope": "read:package,write:repository"}), 4),
    ("scope_no_read_package", _claims({"UserID": 7, "Scope": "read:user"}), 4),
    ("scope_missing_claim", _claims({"UserID": 7}), 4),
    ("userid_missing_claim", _claims({"Scope": "read:package"}), 4),
    ("token_not_a_jwt", _raw_token("opaque-token-value"), 4),
    ("registry_token_401", _token_status(401), 4),
    (
        "scope_403_identity_still_needs_scope",
        lambda w: (_claims({"UserID": 7, "Scope": "all"})(w), _identity(403)(w)),
        4,
    ),
    ("base_id_mismatch", _attr("base_id", "sha256:" + "9" * 64), 5),
    ("containerd_base_id_not_pinned", lambda w: _containerd(w, base_id="sha256:" + "9" * 64), 5),
    ("containerd_base_descriptor_not_pinned", lambda w: _containerd(w, base_digest="sha256:" + "9" * 64), 5),
    ("containerd_base_config_id_not_accepted", lambda w: _containerd(w, base_id=BASE_CONFIG), 5),
    ("containerd_descriptor_not_object", lambda w: setattr(w["docker"], "base_descriptor", "sha256:x"), 5),
    (
        "null_descriptor_falls_back_to_classic_config_pin",
        lambda w: (
            setattr(w["docker"], "base_descriptor_null", True),
            setattr(w["docker"], "base_id", BASE_REF.rpartition("@")[2]),
        ),
        5,
    ),
    ("base_wrong_arch", _attr("base_arch", "arm64"), 5),
    ("base_wrong_os", _attr("base_os", "windows"), 5),
    ("base_layer_count", _attr("base_layers", ["sha256:" + "1" * 64] * 13), 5),
    ("login_failure", _attr("login_code", 1), 6),
    ("pull_failure", _attr("pull_code", 1), 7),
    ("image_id_mismatch", _attr("image_id", "sha256:" + "8" * 64), 9),
    ("containerd_image_id_not_pinned", lambda w: _containerd(w, image_id=CONFIG), 9),
    ("containerd_image_descriptor_not_pinned", lambda w: _containerd(w, image_digest="sha256:" + "8" * 64), 9),
    ("missing_repo_digest", _attr("repo_digests", []), 9),
    ("rootfs_mismatch", _attr("image_layers", ["sha256:" + "7" * 64]), 9),
    ("wrong_os", _attr("os", "windows"), 9),
    ("wrong_arch", _attr("arch", "arm64"), 9),
]


@pytest.mark.parametrize(("label", "mutate", "step"), CASES, ids=[case[0] for case in CASES])
def test_every_refusal_writes_nothing_and_leaks_nothing(world, capsys, label, mutate, step):
    mutate(world)
    with pytest.raises(loader.Refused) as refused:
        _go(world)
    assert refused.value.step == step, label
    assert world["github_env"].read_text() == ""
    printed = capsys.readouterr()
    assert TOKEN not in printed.out + printed.err and "must never be echoed" not in printed.out + printed.err
    scoped = [c["argv"] for c in world["docker"].calls if "--config" in c["argv"]]
    for call in world["docker"].calls:
        assert TOKEN not in " ".join(call["argv"]) + json.dumps(call["env"])
    if step in (6, 7, 9):
        assert [a[3] for a in scoped][-1] == "logout"  # logout and cfg removal ran before any later check
        assert not world["config"].exists()
    else:
        assert not scoped


def test_uncertain_config_removal_refuses_without_export(world, monkeypatch):
    monkeypatch.setattr(loader.shutil, "rmtree", lambda *args, **kwargs: None)
    with pytest.raises(loader.Refused) as refused:
        _go(world)
    assert refused.value.step == 8
    assert world["github_env"].read_text() == ""
    assert [c["argv"][3] for c in world["docker"].calls if "--config" in c["argv"]][-1] == "logout"


def test_existing_config_directory_is_refused_before_login(world):
    world["config"].mkdir()
    with pytest.raises(loader.Refused) as refused:
        _go(world)
    assert refused.value.step == 6
    assert not [c for c in world["docker"].calls if "--config" in c["argv"]]


def test_github_env_must_be_a_regular_file(world, tmp_path):
    link = tmp_path / "linked_env"
    link.symlink_to(world["github_env"])
    world["environ"]["GITHUB_ENV"] = str(link)
    with pytest.raises(loader.Refused) as refused:
        _go(world)
    assert refused.value.step == 0


def test_main_prints_only_the_step_number(monkeypatch, capsys):
    def refuse(*_args: Any, **_kwargs: Any) -> str:
        raise loader.Refused(3)

    monkeypatch.setattr(loader, "materialize", refuse)
    assert loader.main() == 1
    printed = capsys.readouterr()
    assert printed.out == "" and printed.err == "Genesis image materialization refused [P3]\n"


def test_declaration_copy_used_by_the_fixture_is_otherwise_the_committed_one(world):
    committed = _load_declaration()
    used = json.loads((world["root"] / "ci/genesis_image/genesis-image-declaration.json").read_text())
    expected = copy.deepcopy(committed)
    expected["source"]["push_receipt_sha256"] = RECEIPT
    assert used == expected
