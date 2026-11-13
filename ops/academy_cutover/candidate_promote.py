"""Prepared host-local promotion, candidate stop and timer resume; never executed.

Only trusted Linux root system Python -I -S. A pinned root-private reviewed
candidate_execute module supplies stdlib-only technical primitives. No SSH,
installation, migration, approval factory, restore, nginx/firewall/guard edits.
Missing separately reviewed observation producers are hard prerequisites.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

PHASES = ("promote", "stop-new", "resume")
COMMON = None
ACTIVE = None
NGINX_SITE = "/etc/nginx/sites-enabled/academy"
NGINX_FORMAT = "/etc/nginx/conf.d/academy-candidate-path-only.conf"
STATIC_URLS = (
    "/static/academy.js",
    "/static/lifecycle.js",
    "/static/css/toasts.css",
    "/static/css/main.css",
    "/static/js/components.js",
    "/static/js/alpine.min.js",
)


def require(ok, reason="promotion_guard"):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite_json"))


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "strict_fields")


def hexvalue(value, size=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value), "hash_format")


def root_directory(path, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "root_directory_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "root_directory_custody")
        if private:
            require(path.parts[1] == "root" and not os.fstat(fd).st_mode & 0o077, "private_directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def root_read(path, limit=2000000, private=True, mode=None):
    path = Path(path)
    parent = root_directory(path.parent, private=private)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_nlink == 1
                and not info.st_mode & 0o022
                and info.st_size <= limit,
                "root_regular_file",
            )
            require(not private or not info.st_mode & 0o077, "private_file")
            require(mode is None or stat.S_IMODE(info.st_mode) == mode, "exact_file_mode")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            require(
                len(raw) <= limit
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "changed_or_oversized_read",
            )
            return raw
    finally:
        os.close(parent)


def load(path):
    raw = root_read(path)
    return decode(raw), digest(raw)


def load_common(path, expected):
    hexvalue(expected)
    require(Path(path).name == "candidate_execute.py", "common_basename")
    raw = root_read(path)
    require(digest(raw) == expected, "reviewed_common_hash")
    module = types.ModuleType("academy_reviewed_execution_common")
    module.__file__ = str(path)
    # Execute only exact hash-reviewed root-private source already read by fd.
    # Its guarded main does not run. All top-level imports are audited stdlib.
    exec(compile(raw, str(path), "exec"), module.__dict__)  # noqa: S102 -- pinned reviewed stdlib-only module, never candidate code
    return module


def stamp(value):
    require(type(value) in {int, float} and 0 <= time.time() - value < 300, "fresh_start_timestamp")


def units(role):
    return COMMON.services(role)


def approval_live():
    require(
        ACTIVE is not None and ACTIVE["approval"]["approved_unix"] <= time.time() < ACTIVE["approval"]["expires_unix"],
        "approval_expired_before_mutation",
    )


def record_event(kind, detail):
    """Immutable O_EXCL pre-action journal, durable even if later SIGKILL occurs."""
    require(ACTIVE is not None and re.fullmatch(r"[a-z0-9-]{1,80}", kind), "event_context")
    value = dict(
        schema="AcademyPromotionEvent.v1",
        candidate=ACTIVE["manifest"]["candidate"],
        tree=ACTIVE["manifest"]["tree"],
        role=ACTIVE["role"],
        phase=ACTIVE["phase"],
        attempt=ACTIVE["approval"]["attempt"],
        manifest_sha256=ACTIVE["manifest_sha256"],
        approval_sha256=ACTIVE["approval_sha256"],
        intent_sha256=ACTIVE["intent_sha256"],
        event=kind,
        observed_unix_started=time.time(),
        detail=detail,
    )
    name = (
        "promotion-event-"
        + ACTIVE["manifest"]["candidate"]
        + "-"
        + ACTIVE["role"]
        + "-"
        + ACTIVE["phase"]
        + "-"
        + kind
        + ".json"
    )
    COMMON.write_new(ACTIVE["directory"] / name, value)
    ACTIVE["progress"].setdefault("durable_event_sha256", {})[kind] = digest(canonical(value) + b"\n")


def systemctl(action, selected=(), fields=None, cleanup=False):
    allowed_units = set(units("web") + units("lab") + COMMON.timers())
    require(set(selected) <= allowed_units, "fixed_unit_set")
    require(action in {"show", "cat", "stop", "start", "daemon-reload"}, "fixed_systemctl_action")
    if action in {"show", "cat"}:
        require(len(selected) == 1, "read_single_unit")
    if action == "show":
        require(
            fields in {COMMON.PROPS, "MainPID,ActiveState,SubState", "ActiveState,UnitFileState,Unit"},
            "fixed_property_fields",
        )
    if action == "daemon-reload":
        require(not selected and fields is None, "reload_arguments")
    if action in {"stop", "start", "daemon-reload"}:
        if cleanup:
            require(action == "stop" and selected, "cleanup_stop_only")
        else:
            approval_live()
        event_name = action + "-" + digest(canonical(list(selected)))[:16]
        try:
            record_event(event_name, dict(units=list(selected), cleanup=cleanup))
        except BaseException:
            if not cleanup:
                raise
            ACTIVE["progress"]["cleanup_event_unconfirmed"] = True
        if not cleanup:
            approval_live()  # Journal/fsync time cannot extend approval.
    argv = ["/usr/bin/systemctl", action, *selected]
    if fields is not None:
        argv.append("--property=" + fields)
    code, output, _ = COMMON.run_group(argv, COMMON.clean_env(), 90, stdin=subprocess.DEVNULL)
    require(code == 0, "systemctl_failed")
    return output.decode().strip()


def properties(unit, fields=None):
    return dict(row.split("=", 1) for row in systemctl("show", [unit], fields or COMMON.PROPS).splitlines())


def state(unit):
    return properties(unit, "MainPID,ActiveState,SubState")


def normalized_properties(value):
    value = dict(value)
    value["ExecStart"] = COMMON.stable_exec_start(value["ExecStart"])
    return value


def validate_manifest(m, role):
    exact(
        m,
        (
            "schema",
            "candidate",
            "tree",
            "source",
            "venv",
            "previous",
            "recovery",
            "retention",
            "self_sha256",
            "plan_sha256",
            "common_path",
            "common_sha256",
            "execution_manifest",
            "execution_approval",
            "execution_approval_sha256",
            "producers",
            "roles",
            "process_source_pins",
            "review_record",
            "nginx_activation",
        ),
    )
    require(m["schema"] == "AcademyPromotionInputs.v6", "promotion_manifest_schema")
    for key in ("candidate", "tree"):
        hexvalue(m[key], 40)
    for key in ("self_sha256", "plan_sha256", "common_sha256", "execution_approval_sha256"):
        hexvalue(m[key])
    exact(m["execution_manifest"], ("path", "sha256"))
    exact(m["execution_approval"], ("path", "sha256"))
    reference = m["execution_approval"]
    require(
        type(reference["path"]) is str
        and Path(reference["path"]).is_absolute()
        and Path(reference["path"]).parts[1] == "root"
        and ".." not in Path(reference["path"]).parts
        and reference["sha256"] == m["execution_approval_sha256"],
        "original_execution_authority_reference",
    )
    exact(m["review_record"], ("path", "sha256"))
    require(
        digest(root_read(m["review_record"]["path"])) == m["review_record"]["sha256"],
        "independent_promotion_review_record",
    )
    exact(m["producers"], ("candidate_baseline.py", "candidate_process_observer.py", "acceptance_observer"))
    for value in m["producers"].values():
        hexvalue(value)
    contract = m["nginx_activation"]
    exact(contract, ("helper_sha256", "site_path", "site_sha256", "format_path", "format_sha256", "assets"))
    for key in ("helper_sha256", "site_sha256", "format_sha256"):
        hexvalue(contract[key])
    require(
        contract["site_path"] == NGINX_SITE and contract["format_path"] == NGINX_FORMAT, "fixed_nginx_contract_paths"
    )
    require(
        type(contract["assets"]) is list
        and len(contract["assets"]) == 6
        and {item["url"] for item in contract["assets"]} == set(STATIC_URLS),
        "fixed_expected_static_asset_contract",
    )
    for asset in contract["assets"]:
        exact(asset, ("url", "sha256", "source_path", "installed_path", "wheel_path", "wheel_member"))
        hexvalue(asset["sha256"])
        if asset["url"] in STATIC_URLS[:2]:
            require(
                asset["source_path"] == m["source"] + asset["url"]
                and asset["installed_path"] is None
                and asset["wheel_path"] is None
                and asset["wheel_member"] is None,
                "product_static_contract_source",
            )
        else:
            require(
                asset["source_path"] is None
                and type(asset["installed_path"]) is str
                and asset["installed_path"].startswith(m["venv"] + "/lib/python3.12/site-packages/")
                and type(asset["wheel_path"]) is str
                and asset["wheel_path"].startswith("/root/")
                and type(asset["wheel_member"]) is str
                and not Path(asset["wheel_member"]).is_absolute()
                and ".." not in Path(asset["wheel_member"]).parts
                and asset["wheel_member"].endswith(asset["url"]),
                "kernel_static_contract_parity",
            )
    exact(m["roles"], ("web", "lab"))
    for host_role, spec in m["roles"].items():
        exact(spec, ("hostname", "units", "effective_environment_sha256", "runtime_baseline"))
        exact(spec["units"], units(host_role))
        hexvalue(spec["effective_environment_sha256"])
        for target in spec["units"].values():
            exact(
                target,
                (
                    "old_properties_sha256",
                    "new_properties_sha256",
                    "old_unit_sha256",
                    "command_sha256",
                    "override_sha256",
                    "environment_files",
                    "inline_environment_sha256",
                    "effective_values_sha256",
                    "reviewed_custom_import_controls",
                ),
            )
            for key in (
                "old_properties_sha256",
                "new_properties_sha256",
                "old_unit_sha256",
                "command_sha256",
                "override_sha256",
                "inline_environment_sha256",
            ):
                hexvalue(target[key])
            require(
                type(target["environment_files"]) is list and len(target["environment_files"]) <= 10,
                "environment_file_count",
            )
            for item in target["environment_files"]:
                exact(item, ("path", "sha256"))
                hexvalue(item["sha256"])
                require(
                    type(item["path"]) is str
                    and Path(item["path"]).is_absolute()
                    and ".." not in Path(item["path"]).parts,
                    "environment_file_path",
                )
            for name in ("effective_values_sha256", "reviewed_custom_import_controls"):
                require(
                    type(target[name]) is dict
                    and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) for k in target[name]),
                    "environment_control_map",
                )
                for value in target[name].values():
                    hexvalue(value)
    exact(m["process_source_pins"], ("app/config.py", "pyproject.toml", "poetry.lock"))
    for value in m["process_source_pins"].values():
        hexvalue(value)
    require(m["roles"][role]["hostname"] == socket.gethostname(), "exact_host")


def _authorization_bindings(a, m, manifest_hash, phase):
    exact(
        a,
        (
            "schema",
            "approved_by",
            "approval_id",
            "approval_record_path",
            "approval_record_sha256",
            "attempt",
            "approved_unix",
            "expires_unix",
            "manifest_sha256",
            "plan_sha256",
            "promoter_sha256",
            "common_sha256",
            "producers",
            "execution_approval_sha256",
            "candidate",
            "tree",
            "source",
            "venv",
            "previous",
            "recovery",
            "retention",
            "authorized_phases",
        ),
    )
    require(a["schema"] == "AcademyPromotionApproval.v1" and a["approved_by"] == "Michael", "actual_approval_required")
    require(type(a["approval_id"]) is str and re.fullmatch(r"[A-Za-z0-9-]{8,100}", a["approval_id"]), "approval_id")
    hexvalue(a["attempt"])
    require(digest(root_read(a["approval_record_path"])) == a["approval_record_sha256"], "actual_approval_record")
    require(
        a["manifest_sha256"] == manifest_hash
        and a["plan_sha256"] == m["plan_sha256"]
        and a["promoter_sha256"] == m["self_sha256"]
        and a["common_sha256"] == m["common_sha256"]
        and a["producers"] == m["producers"]
        and a["execution_approval_sha256"] == m["execution_approval_sha256"],
        "approval_hash_bindings",
    )
    for key in ("candidate", "tree", "source", "venv", "previous", "recovery", "retention"):
        require(a[key] == m[key], "approval_identity")
    require(
        type(a["authorized_phases"]) is list
        and len(set(a["authorized_phases"])) == len(a["authorized_phases"])
        and set(a["authorized_phases"]) <= set(PHASES)
        and phase in a["authorized_phases"],
        "authorized_phase",
    )


def authorization(a, m, manifest_hash, phase):
    _authorization_bindings(a, m, manifest_hash, phase)
    require(
        type(a["approved_unix"]) is int
        and type(a["expires_unix"]) is int
        and a["approved_unix"] <= time.time() < a["expires_unix"] <= a["approved_unix"] + 3600,
        "approval_window",
    )


def authorization_at_observation(a, m, manifest_hash, phase, started, finished):
    _authorization_bindings(a, m, manifest_hash, phase)
    require(
        type(started) is int
        and type(finished) is int
        and 0 <= started <= finished <= time.time(),
        "historical_observation_interval",
    )
    require(
        type(a["approved_unix"]) is int
        and type(a["expires_unix"]) is int
        and a["approved_unix"] < a["expires_unix"] <= a["approved_unix"] + 3600
        and a["approved_unix"] <= started <= finished < a["expires_unix"],
        "historical_approval_window",
    )


class Evidence:
    def __init__(self, path, m, cm, a, approval_hash, manifest_hash, execution_manifest_hash):
        self.value, self.sha256 = load(path)
        self.promoter, self.m, self.a = m, cm, a
        self.promotion_approval_hash, self.promotion_manifest_hash = approval_hash, manifest_hash
        self.approval_hash, self.manifest_hash = m["execution_approval_sha256"], execution_manifest_hash
        self.execution_manifest_hash = execution_manifest_hash
        self.execution_approval = dict(m["execution_approval"])
        self.used = {}
        self.active_catalog_observations = []
        require(
            cm["helpers"].get("candidate_nginx.py") == m["nginx_activation"]["helper_sha256"],
            "nginx_common_static_helper_pin",
        )
        exact(self.value, ("schema", "candidate", "tree", "attempt", "created_unix", "entries"))
        require(self.value["schema"] == "AcademyPromotionEvidenceIndex.v1", "promotion_evidence_schema")
        require(
            self.value["candidate"] == m["candidate"]
            and self.value["tree"] == m["tree"]
            and self.value["attempt"] == a["attempt"],
            "evidence_identity",
        )
        stamp(self.value["created_unix"])
        self.producers = {
            **cm["helpers"],
            **m["producers"],
            "candidate_maintenance.py": cm["helpers"]["maintenance"]["sha256"],
            "candidate_execute.py": cm["self_sha256"],
            "candidate_promote.py": m["self_sha256"],
        }
        require(type(self.value["entries"]) is dict and len(self.value["entries"]) <= 80, "evidence_count")
        for name, item in self.value["entries"].items():
            require(
                re.fullmatch(r"[a-z][a-z0-9-]{1,80}", name) or name == "maintenance-lab-adopted_and_fenced",
                "evidence_name",
            )
            descriptor_fields = {"path", "sha256", "producer", "producer_sha256", "role", "observed_unix"}
            if name == "nginx-apply":
                descriptor_fields.add("supporting_inputs")
                require(
                    type(item.get("path")) is str and Path(item["path"]).name.endswith("-result.json"),
                    "nginx_actual_result_filename",
                )
                require(
                    item.get("producer") == "candidate_nginx.py" and item.get("role") == "web",
                    "actual_nginx_result_producer",
                )
                exact(item["supporting_inputs"], ("manifest", "approval"))
                for artifact in item["supporting_inputs"].values():
                    exact(artifact, ("path", "sha256"))
                    hexvalue(artifact["sha256"])
            exact(item, descriptor_fields)
            hexvalue(item["sha256"])
            require(
                item["producer"] in self.producers
                and item["producer_sha256"] == self.producers[item["producer"]]
                and item["role"] in {"web", "lab"},
                "evidence_producer",
            )

    def validate_historical_promotion(self, a, m, manifest_hash, phase, started, finished):
        # The caller reopens historical pins. Reopen current protected pins and
        # require their exact byte hashes, even when historical paths differ.
        active = self.active_authority
        require(active["kind"] == "promotion" and active["phase"] == phase, "historical_same_promotion_phase")
        current_manifest, current_manifest_hash = load(active["manifest"]["path"])
        require(
            current_manifest_hash == active["manifest"]["sha256"] == self.promotion_manifest_hash == manifest_hash
            and current_manifest == self.promoter == m,
            "historical_identical_promotion_manifest",
        )
        current, current_hash = load(active["approval"]["path"])
        require(
            current_hash == active["approval"]["sha256"] == self.promotion_approval_hash and current == self.a,
            "historical_current_promotion_approval",
        )
        authorization(current, current_manifest, current_manifest_hash, phase)
        execution_ref = current_manifest["execution_manifest"]
        execution, execution_hash = load(execution_ref["path"])
        original_ref = current_manifest["execution_approval"]
        original, original_hash = load(original_ref["path"])
        require(
            execution_hash == execution_ref["sha256"] == self.manifest_hash
            and execution == self.m
            and original_ref == self.execution_approval
            and original_hash == original_ref["sha256"] == self.approval_hash
            and current_manifest["execution_approval_sha256"] == original_hash,
            "historical_original_execution_parent",
        )
        COMMON.approval(original, execution_hash, execution, "quiesce", historical=True)
        authorization_at_observation(a, m, manifest_hash, phase, started, finished)
        require(
            all(
                a[key] == current[key] == original[key]
                for key in ("attempt", "approval_record_path", "approval_record_sha256")
            ),
            "historical_same_actual_human_record_attempt",
        )

    def get(self, name, producer, role, fresh=True):
        value = self._get_raw(name, producer, role, fresh=fresh)
        if producer == "external_census":
            require(not name.startswith("sources-"), "census_sources_require_raw_read")
            COMMON.census_module(self.m).verify_receipt_sources(
                COMMON.common_api(), self.m, self, name, value, self.used[name]["sha256"], fresh
            )
        return value

    def _get_raw(self, name, producer, role, fresh=True):
        require(name in self.value["entries"], "missing_actual_producer_receipt")
        item = self.value["entries"][name]
        require(item["producer"] == producer and item["role"] == role, "producer_role")
        if fresh:
            stamp(item["observed_unix"])
        raw = root_read(item["path"], limit=100000000)
        require(digest(raw) == item["sha256"], "receipt_hash")
        value = decode(raw)
        self.used[name] = dict(
            sha256=item["sha256"],
            producer_sha256=item["producer_sha256"],
            role=role,
            observed_unix=item["observed_unix"],
        )
        return value

    def phase(self, name, role, expected_phase, fresh=True):
        return COMMON.Evidence.phase(self, name, role, expected_phase, fresh=fresh)

    def promoted(self, role, fresh=False):
        value = self.get("promoted-" + role, "candidate_promote.py", role, fresh=fresh)
        exact(
            value,
            (
                "schema",
                "status",
                "phase",
                "role",
                "candidate",
                "tree",
                "attempt",
                "approval_sha256",
                "manifest_sha256",
                "evidence_index_sha256",
                "intent_sha256",
                "started_unix",
                "completed_unix",
                "evidence",
                "observations",
                "process_groups",
                "deployment_ready",
            ),
        )
        require(
            value["schema"] == "AcademyPromotionReceipt.v1"
            and value["status"] == "observed"
            and value["phase"] == "promote"
            and value["role"] == role
            and value["candidate"] == self.m["candidate"]
            and value["tree"] == self.m["tree"]
            and value["attempt"] == self.a["attempt"]
            and value["manifest_sha256"] == self.promotion_manifest_hash
            and value["approval_sha256"] == self.promotion_approval_hash
            and value["deployment_ready"] is False,
            "promoted_receipt",
        )
        require(all(x["confirmed"] is True for x in value["process_groups"]), "promotion_process_cleanup")
        if fresh:
            stamp(value["completed_unix"])
        return value


def environment_assignments(text):
    """Conservative systemd literal assignment subset; never evaluate shell text."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        require("=" in line and "\\" not in line and "\x00" not in line, "unsupported_environment_file_syntax")
        key, raw = line.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in result, "environment_assignment_key")
        if raw.startswith(("'", '"')):
            require(len(raw) >= 2 and raw[-1] == raw[0], "whole_value_quote_required")
        else:
            require("'" not in raw and '"' not in raw, "embedded_quote_requires_review")
        parts = shlex.split(raw, comments=False, posix=True)
        require(len(parts) <= 1, "environment_literal_requires_review")
        result[key] = parts[0] if parts else ""
    return result


def inline_environment(raw):
    require("\\" not in raw and "\n" not in raw and "\x00" not in raw, "inline_environment_syntax")
    result = {}
    for item in shlex.split(raw, comments=False):
        require("=" in item, "inline_assignment")
        key, value = item.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in result, "inline_duplicate_or_key")
        result[key] = value
    return result


def runtime_for(m, role):
    """Descriptor validated and byte-joined to the common manifest before actions."""
    require(role in ("web", "lab"), "runtime_role")
    return m["roles"][role]["runtime_baseline"]


def environment_controls(values, m, target, runtime, runtime_unit, old=False):
    custom = target["reviewed_custom_import_controls"]
    prior_paths = COMMON.PRIOR_PATHS
    for key, value in values.items():
        if key == "PYTHONPATH":
            allowed = {"", m["source"], runtime_unit["source"]} if old else {"", m["source"]}
            require(value in allowed, "pythonpath_requires_review")
        elif key == "PYTHONHOME":
            require(value == "", "pythonhome_refused")
        elif key.startswith(("PYTHON", "LD_", "DYLD_", "PG")):
            require(False, "python_ld_pg_control_refused")
        elif key == "VIRTUAL_ENV":
            allowed = {"", m["venv"], runtime_unit["venv"]} if old else {"", m["venv"]}
            require(value in allowed, "virtual_env_exact_runtime")
            require(custom.get(key) == digest(value.encode()), "virtual_env_reviewed_value")
        elif key == "PATH":
            require(value and custom.get(key) == digest(value.encode()), "path_reviewed_value")
            for entry in value.split(":"):
                require(
                    entry and Path(entry).is_absolute() and ".." not in Path(entry).parts, "path_absolute_components"
                )
                allowed_bins = {m["venv"] + "/bin"}
                if old:
                    allowed_bins.add(runtime_unit["venv"] + "/bin")
                if entry not in allowed_bins:
                    resolved = Path(entry).resolve(strict=True)
                    fd = root_directory(resolved)
                    os.close(fd)
        elif re.search(r"(MODULE|IMPORT|CONFIG|PATH|DIRECTORY|HOME|ROOT)", key):
            require(custom.get(key) == digest(value.encode()), "custom_import_control_requires_review")
        for prior in prior_paths:
            if prior not in value:
                continue
            old_control = old and (
                (key == "PYTHONPATH" and value == runtime_unit["source"])
                or (key == "VIRTUAL_ENV" and value == runtime_unit["venv"])
                or (
                    key == "PATH"
                    and prior == runtime_unit["venv"]
                    and all(prior not in part or part == runtime_unit["venv"] + "/bin" for part in value.split(":"))
                )
            )
            envfile_control = value == runtime["environment"]["target"] and custom.get(key) == digest(value.encode())
            require(old_control or envfile_control, "retained_import_path_refused")


def effective_environment(props, target, m, runtime, runtime_unit, old):
    require(
        not props["PassEnvironment"].strip() and not props["UnsetEnvironment"].strip(),
        "manager_pass_or_unset_requires_review",
    )
    inline = inline_environment(props["Environment"])
    if old:
        require(
            digest(canonical({k: digest(v.encode()) for k, v in inline.items()}))
            == target["inline_environment_sha256"],
            "inline_environment_drift",
        )
    environment_controls(inline, m, target, runtime, runtime_unit, old=old)
    raw_files = props["EnvironmentFiles"]
    names = re.findall(r"(/[^\s]+) \(ignore_errors=(?:yes|no)\)", raw_files)
    require(
        not re.sub(r"(/[^\s]+) \(ignore_errors=(?:yes|no)\)", "", raw_files).strip(), "environment_files_representation"
    )
    require(names == [item["path"] for item in target["environment_files"]], "effective_environment_file_order")
    descriptor = runtime["environment"]
    COMMON.observed_environment(runtime)
    candidate_env = Path(m["source"]) / ".env"
    require(
        candidate_env.is_symlink() and os.readlink(candidate_env) == descriptor["target"], "exact_candidate_env_link"
    )
    merged = dict(inline)
    for item in target["environment_files"]:
        path = Path(item["path"])
        if str(path) in {str(candidate_env), descriptor["path"], descriptor["target"]}:
            require(item["sha256"] == descriptor["sha256"], "environment_descriptor_hash_join")
            path = Path(descriptor["target"])
        else:
            require(not any(prior in str(path) for prior in COMMON.PRIOR_PATHS), "undeclared_prior_environment_file")
        raw = COMMON.read_bytes(path, limit=2000000)
        require(digest(raw) == item["sha256"], "effective_environment_file_bytes")
        values = environment_assignments(raw.decode())
        # Files override Environment=; drop-ins cannot correct old import paths here.
        environment_controls(values, m, target, runtime, runtime_unit, old=False)
        merged.update(values)
    hashed = {k: digest(v.encode()) for k, v in merged.items()}
    expected = dict(target["effective_values_sha256"])
    if not old:
        expected["PYTHONPATH"] = digest(m["source"].encode())
    require(hashed == expected, "complete_effective_environment_values")
    return merged


def unit_proposal(unit, target, m, role):
    runtime = runtime_for(m, role)
    runtime_unit = runtime["units"][unit]
    old_props = properties(unit)
    require(
        old_props["WorkingDirectory"] == runtime_unit["source"] and old_props["User"] == "dotmac",
        "old_unit_source_user",
    )
    require(
        digest(canonical(normalized_properties(old_props))) == target["old_properties_sha256"], "full_old_configuration"
    )
    old_text = systemctl("cat", [unit])
    require(digest(old_text.encode()) == target["old_unit_sha256"], "old_unit_text")
    environment = effective_environment(old_props, target, m, runtime, runtime_unit, old=True)
    proposed_environment = {**environment, "PYTHONPATH": m["source"]}
    environment_controls(proposed_environment, m, target, runtime, runtime_unit, old=False)
    text = COMMON.render_override(unit, COMMON.configured_start(old_text), target["command_sha256"], runtime_unit)
    require(digest(text.encode()) == target["override_sha256"], "reviewed_override_bytes")
    return dict(
        unit=unit,
        text=text,
        environment_sha256=digest(canonical({k: digest(v.encode()) for k, v in environment.items()})),
    )


def dropin_path(unit, m):
    require(unit in set(units("web") + units("lab")), "dropin_unit")
    return Path("/etc/systemd/system") / (unit + ".service.d") / ("90-academy-candidate-" + m["candidate"] + ".conf")


def write_override(proposal, m):
    path = dropin_path(proposal["unit"], m)
    approval_live()
    record_event(
        "override-" + proposal["unit"], dict(unit=proposal["unit"], override_sha256=digest(proposal["text"].encode()))
    )
    approval_live()
    base = root_directory(path.parent.parent)
    try:
        try:
            os.mkdir(path.parent.name, 0o700, dir_fd=base)
        except FileExistsError:
            pass
        else:
            created = os.open(
                path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base
            )
            try:
                opened = os.fstat(created)
                named = os.stat(path.parent.name, dir_fd=base, follow_symlinks=False)
                require(
                    opened.st_uid == 0
                    and stat.S_ISDIR(opened.st_mode)
                    and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino),
                    "fresh_dropin_directory_identity",
                )
                os.fchmod(created, 0o755)  # Only the just-created inode, never existing directory.
                os.fsync(created)
                os.fsync(base)
            finally:
                os.close(created)
    finally:
        os.close(base)
    parent = root_directory(path.parent)
    try:
        approval_live()
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent
        )
        with os.fdopen(fd, "wb") as output:
            info = os.fstat(output.fileno())
            require(
                info.st_uid == 0 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "fresh_dropin_file_identity"
            )
            os.fchmod(output.fileno(), 0o644)  # O_EXCL-created FD; independent of root umask077.
            output.write(proposal["text"].encode())
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def installed_candidate_configuration(role, m):
    primary = units(role)[0]
    target = m["roles"][role]["units"][primary]
    props = properties(primary)
    require(
        props["WorkingDirectory"] == m["source"]
        and props["User"] == "dotmac"
        and digest(canonical(normalized_properties(props))) == target["new_properties_sha256"],
        "cleanup_exact_installed_candidate_config",
    )
    require(
        digest(root_read(dropin_path(primary, m), private=False, mode=0o644)) == target["override_sha256"],
        "cleanup_exact_candidate_dropin",
    )
    return props


def candidate_ownership(role, m, cm):
    """Ownership only: independent of OIDC, settings and observer health."""
    installed_candidate_configuration(role, m)
    primary = units(role)[0]
    observed = state(primary)
    require(observed["MainPID"].isdigit(), "candidate_ownership_mainpid")
    pid = int(observed["MainPID"])
    if pid == 0:
        require(
            observed["ActiveState"] in {"inactive", "failed", "activating", "deactivating"}, "candidate_pending_state"
        )
        require(state(primary) == observed, "candidate_pending_state_changed")
        return dict(
            unit=primary, pid=0, start_ticks=None, state=observed, ownership="exact_candidate_config_pending_or_stopped"
        )
    require(pid > 1, "candidate_ownership_pid")
    proc = Path("/proc") / str(pid)
    ticks = COMMON.proc_ticks(pid)
    require(
        proc.stat().st_uid == cm["roles"][role]["uid"]
        and os.readlink(proc / "cwd") == m["source"]
        and os.readlink(proc / "exe") == "/usr/bin/python3.12",
        "candidate_ownership_uid_cwd_exe",
    )
    argv_raw = COMMON.proc_bytes(proc / "cmdline")
    argv = [part.decode() for part in argv_raw.rstrip(b"\0").split(b"\0")]
    configured = shlex.split(COMMON.configured_start(systemctl("cat", [primary])), comments=False)
    allowed_python = {m["venv"] + "/bin/" + name for name in ("python", "python3", "python3.12")}
    require(
        configured and configured[0].startswith(m["venv"] + "/bin/") and argv, "candidate_ownership_configured_argv"
    )
    # Exact argv proves normal ownership. Candidate interpreter/script prefix
    # also identifies an unhealthy process with changed later arguments; it may
    # be stopped but must never qualify as a healthy promotion.
    prefix_owned = argv[0] == configured[0] or (
        argv[0] in allowed_python and len(argv) > 1 and (argv[1] == configured[0] or configured[0] in allowed_python)
    )
    require(
        prefix_owned
        and not any(prior in arg for arg in argv for prior in COMMON.baseline_module(cm).forbidden_runtime_paths()),
        "candidate_ownership_argv_anchor",
    )
    require(COMMON.proc_ticks(pid) == ticks and state(primary) == observed, "candidate_ownership_stable_ticks")
    installed_candidate_configuration(role, m)
    return dict(
        unit=primary,
        pid=pid,
        start_ticks=ticks,
        argv_sha256=digest(argv_raw),
        ownership="exact_candidate_config_and_live_process",
    )


def stop_owned_candidate(role, m, cm, cleanup=False):
    identity = candidate_ownership(role, m, cm)
    try:
        record_event(
            "candidate-stop-ownership",
            dict(
                unit=identity["unit"],
                pid=identity["pid"],
                start_ticks=identity["start_ticks"],
                identity_sha256=digest(canonical(identity)),
            ),
        )
    except BaseException:
        if not cleanup:
            raise
        ACTIVE["progress"]["cleanup_event_unconfirmed"] = True
    # Fixed unit control only, never arbitrary PID signalling, guard or old unit.
    systemctl("stop", [units(role)[0]], cleanup=cleanup)
    deadline = time.monotonic() + 30
    while state(units(role)[0]) != dict(MainPID="0", ActiveState="inactive", SubState="dead"):
        require(time.monotonic() < deadline, "candidate_stop_not_confirmed")
        time.sleep(0.2)
    stopped = COMMON.stopped(role, cm)
    return dict(identity=identity, stopped=stopped)


def failed_start_cleanup(role, m, cm, a, evidence):
    result = dict(
        confirmed=False, manual_hold=True, old_restart_performed=False, overrides_retained=True, gate_reheld=False
    )
    try:
        result["candidate_stop"] = stop_owned_candidate(role, m, cm, cleanup=True)
        result["preserved"] = COMMON.preserved(role, cm)
        if role == "web":
            paused_timers()
        result["gate"] = held_gate(role, m, cm, a, evidence)
        result["confirmed"] = not ACTIVE["progress"].get("cleanup_event_unconfirmed", False) and all(
            group.get("confirmed") is True for group in COMMON.PROCESS_GROUPS
        )
        result["manual_hold"] = not result["confirmed"]
    except BaseException:
        result["ownership_or_cleanup_unconfirmed"] = True
    return result


def validate_new_unit(unit, target, m, role):
    props = properties(unit)
    require(props["WorkingDirectory"] == m["source"] and props["User"] == "dotmac", "new_effective_source_user")
    require(
        digest(canonical(normalized_properties(props))) == target["new_properties_sha256"],
        "actual_new_effective_configuration",
    )
    require(
        root_read(dropin_path(unit, m), private=False, mode=0o644)
        and digest(root_read(dropin_path(unit, m), private=False, mode=0o644)) == target["override_sha256"],
        "installed_override_hash",
    )
    runtime = runtime_for(m, role)
    values = effective_environment(props, target, m, runtime, runtime["units"][unit], old=False)
    require(values.get("PYTHONPATH") == m["source"], "actual_new_import_path")
    return values


def import_environment(environ):
    return {
        k: digest(v.encode())
        for k, v in environ.items()
        if k.startswith(("PYTHON", "LD_", "PG")) or k in {"VIRTUAL_ENV", "PATH"}
    }


def new_process(role, m, cm, environment):
    primary = units(role)[0]
    value = state(primary)
    require(
        value["ActiveState"] == "active" and value["SubState"] == "running" and value["MainPID"].isdigit(),
        "candidate_primary_running",
    )
    pid = int(value["MainPID"])
    ticks = COMMON.proc_ticks(pid)
    proc = Path("/proc") / str(pid)
    require(
        proc.stat().st_uid == cm["roles"][role]["uid"]
        and os.readlink(proc / "cwd") == m["source"]
        and os.readlink(proc / "exe") == "/usr/bin/python3.12",
        "candidate_process_identity",
    )
    argv_raw = COMMON.proc_bytes(proc / "cmdline")
    argv = [part.decode() for part in argv_raw.rstrip(b"\0").split(b"\0")]
    configured = COMMON.configured_start(systemctl("cat", [primary]))
    expected = shlex.split(configured, comments=False)
    allowed_python = [m["venv"] + "/bin/" + name for name in ("python", "python3", "python3.12")]
    require(argv == expected or (argv and argv[0] in allowed_python and argv[1:] == expected), "candidate_actual_argv")
    require(
        any(value.startswith(m["venv"] + "/bin/") for value in argv[:2])
        and not any(prior in value for value in argv for prior in COMMON.baseline_module(cm).forbidden_runtime_paths()),
        "candidate_argv_import_authority",
    )
    environ_raw = COMMON.proc_bytes(proc / "environ", 2000000)
    pairs = environ_raw.rstrip(b"\0").split(b"\0")
    environ = {}
    for pair in pairs:
        require(b"=" in pair, "process_environment_format")
        key, val = pair.split(b"=", 1)
        key, val = key.decode(), val.decode()
        require(key not in environ, "process_environment_duplicate")
        environ[key] = val
    require(all(environ.get(k) == v for k, v in environment.items()), "actual_effective_environment_values")
    runtime = runtime_for(m, role)
    environment_controls(environ, m, m["roles"][role]["units"][primary], runtime, runtime["units"][primary], old=False)
    require(
        environ.get("PYTHONPATH") == m["source"] and COMMON.proc_ticks(pid) == ticks and state(primary) == value,
        "stable_new_process_import_environment",
    )
    return dict(
        pid=pid,
        start_ticks=ticks,
        unit=primary,
        argv_sha256=digest(argv_raw),
        import_environment_sha256=digest(canonical(import_environment(environ))),
        environment_values_sha256=digest(canonical({k: digest(v.encode()) for k, v in environment.items()})),
    )


def observer_path(m):
    path = Path("/usr/local/lib/academy-deploy") / m["candidate"] / "candidate_process_observer.py"
    require(
        digest(root_read(path, private=False, mode=0o644)) == m["producers"]["candidate_process_observer.py"],
        "process_observer_separate_provisioning_required",
    )
    return path


def process_report(report, m, cm, a, role, identity=None):
    exact(
        report,
        (
            "schema",
            "ok",
            "candidate",
            "tree",
            "source",
            "venv",
            "hostname",
            "uid",
            "pid",
            "start_ticks",
            "attempt",
            "helper_sha256",
            "source_file_sha256",
            "env_sha256",
            "environment_file",
            "python_sha256",
            "venv_cfg_sha256",
            "import_environment_sha256",
            "oidc_enabled",
            "oidc_client_secret_present",
            "revision_vector",
            "observed_unix_started",
            "observed_unix_finished",
            "unmet_predicates",
        ),
    )
    require(
        report["schema"] == "AcademyCandidateProcessReport.v2"
        and report["ok"] is True
        and report["unmet_predicates"] == [],
        "new_process_observer_report",
    )
    for key in ("candidate", "tree", "source", "venv"):
        require(report[key] == m[key], "new_process_candidate")
    require(
        report["attempt"] == a["attempt"]
        and report["hostname"] == cm["roles"][role]["hostname"]
        and report["uid"] == cm["roles"][role]["uid"]
        and report["helper_sha256"] == m["producers"]["candidate_process_observer.py"]
        and report["source_file_sha256"] == m["process_source_pins"],
        "process_source_identity",
    )
    require(
        report["env_sha256"] == cm["roles"][role]["environment_sha256"]
        and report["environment_file"] == COMMON.retained_environment_target(cm, role)
        and report["python_sha256"] == cm["roles"][role]["python_sha256"],
        "process_runtime_pins",
    )
    require(
        report["oidc_enabled"] is False
        and report["oidc_client_secret_present"] is False
        and report["revision_vector"] == ["0031_rate_limit_buckets", "a0011_oidc_login_states"],
        "actual_oidc_dark_schema",
    )
    require(
        type(report["pid"]) is int
        and report["pid"] > 1
        and type(report["start_ticks"]) is str
        and report["start_ticks"].isdigit(),
        "process_pid_ticks",
    )
    stamp(report["observed_unix_started"])
    require(
        report["observed_unix_started"] <= report["observed_unix_finished"] <= time.time(), "process_observation_order"
    )
    if identity:
        require(
            report["pid"] == identity["pid"]
            and report["start_ticks"] == identity["start_ticks"]
            and report["import_environment_sha256"] == identity["import_environment_sha256"],
            "process_actual_root_observer_match",
        )
    return report


def observe_process(role, m, cm, a, identity):
    path = observer_path(m)
    value = dict(
        schema="AcademyCandidateProcessInputs.v2",
        candidate=m["candidate"],
        tree=m["tree"],
        source=m["source"],
        venv=m["venv"],
        hostname=cm["roles"][role]["hostname"],
        uid=cm["roles"][role]["uid"],
        pid=identity["pid"],
        start_ticks=identity["start_ticks"],
        attempt=a["attempt"],
        helper_sha256=m["producers"]["candidate_process_observer.py"],
        source_file_sha256=m["process_source_pins"],
        env_sha256=cm["roles"][role]["environment_sha256"],
        environment_file=COMMON.retained_environment_target(cm, role),
        python_sha256=cm["roles"][role]["python_sha256"],
        venv_cfg_sha256=digest(COMMON.read_bytes(Path(m["venv"]) / "pyvenv.cfg")),
        import_environment_sha256=identity["import_environment_sha256"],
    )
    owner = COMMON.pwd.getpwnam("dotmac")
    env = COMMON.clean_env()
    env.update(HOME=owner.pw_dir, USER="dotmac", LOGNAME="dotmac", PATH=m["venv"] + "/bin:/usr/bin:/bin")
    launch = time.time()
    code, out, _ = COMMON.run_group(
        [m["venv"] + "/bin/python", "-I", "-B", str(path)],
        env,
        120,
        cwd=m["source"],
        user=owner.pw_uid,
        group=owner.pw_gid,
        extra_groups=[],
        umask=0o077,
        input_bytes=canonical(value),
    )
    require(code == 0 and len(out) <= 2000000, "process_observer_failed")
    report = process_report(decode(out), m, cm, a, role, identity)
    require(report["venv_cfg_sha256"] == value["venv_cfg_sha256"], "process_venv_cfg")
    stamp(min(launch, report["observed_unix_started"]))
    return dict(input_sha256=digest(canonical(value)), stdout_sha256=digest(out), report=report)


def held_gate(role, m, cm, a, evidence, *, maintenance_status=None):
    if role == "web":
        require(maintenance_status is None, "web_maintenance_status_override")
        return COMMON.gate(evidence, cm, a, role)
    maintenance_status = maintenance_status or "adopted_and_fenced"
    require(role == "lab" and maintenance_status in {"fenced", "adopted_and_fenced"}, "lab_maintenance_gate_status")
    gate = evidence.get("gate-web", "external_census", "web")
    exact(
        gate,
        (
            "schema",
            "candidate",
            "tree",
            "attempt",
            "hostname",
            "observed_unix_started",
            "hold_id",
            "owner_record_sha256",
            "gate_approval_sha256",
            "supervisor_pid",
            "supervisor_start_ticks",
            "lock_inode",
            "lock_kernel_row",
            "state_sha256",
        ),
    )
    require(
        gate["schema"] == "AcademyRootGateObservation.v1"
        and gate["candidate"] == m["candidate"]
        and gate["tree"] == m["tree"]
        and gate["attempt"] == a["attempt"]
        and gate["hostname"] == cm["roles"]["web"]["hostname"]
        and gate["state_sha256"] == digest(b"HELD\n"),
        "remote_actual_gate_observation",
    )
    stamp(gate["observed_unix_started"])
    for key in ("hold_id", "owner_record_sha256", "gate_approval_sha256"):
        hexvalue(gate[key])
    require(
        type(gate["supervisor_pid"]) is int
        and gate["supervisor_pid"] > 1
        and type(gate["supervisor_start_ticks"]) is str
        and gate["supervisor_start_ticks"].isdigit(),
        "remote_gate_supervisor",
    )
    require(
        type(gate["lock_inode"]) is list
        and len(gate["lock_inode"]) == 2
        and all(type(x) is int for x in gate["lock_inode"]),
        "remote_gate_inode",
    )
    words = gate["lock_kernel_row"].split()
    require(
        len(words) == 8
        and words[1:5] == ["FLOCK", "ADVISORY", "WRITE", str(gate["supervisor_pid"])]
        and words[5]
        == f"{os.major(gate['lock_inode'][0]):02x}:{os.minor(gate['lock_inode'][0]):02x}:{gate['lock_inode'][1]}"
        and words[6:] == ["0", "EOF"],
        "remote_kernel_exclusive_lease",
    )
    exclusion = COMMON.exclusion(evidence, cm, a, role, maintenance_status)
    require(
        all(gate[key] == exclusion[key] for key in ("hold_id", "owner_record_sha256", "gate_approval_sha256")),
        "remote_gate_attempt_exclusion",
    )
    return gate


def nginx_disk_identity(m):
    contract = m["nginx_activation"]
    site = root_read(NGINX_SITE, private=False, mode=0o644)
    format_bytes = root_read(NGINX_FORMAT, private=False, mode=0o644)
    require(
        digest(site) == contract["site_sha256"] and digest(format_bytes) == contract["format_sha256"],
        "actual_expected_nginx_site_and_format",
    )
    return dict(site_sha256=digest(site), format_sha256=digest(format_bytes))


def nginx_live_identity():
    raw = root_read("/run/nginx.pid", limit=128, private=False)
    require(re.fullmatch(rb"[1-9][0-9]*\n?", raw), "current_nginx_master_pid")
    pid = int(raw)
    ticks = COMMON.proc_ticks(pid)
    require(
        Path("/proc", str(pid)).stat().st_uid == 0 and os.readlink("/proc/" + str(pid) + "/exe") == "/usr/sbin/nginx",
        "current_nginx_root_master_exe",
    )
    raw_children = COMMON.proc_bytes(Path("/proc") / str(pid) / "task" / str(pid) / "children").split()
    require(0 < len(raw_children) <= 1000, "current_nginx_children_bound")
    children, roles = {}, {}
    titles = {
        b"nginx: worker process": "worker",
        b"nginx: worker process is shutting down": "draining-worker",
        b"nginx: cache manager process": "cache-manager",
        b"nginx: cache loader process": "cache-loader",
    }
    for raw_child in raw_children:
        child = int(raw_child)
        start = COMMON.proc_ticks(child)
        title = COMMON.proc_bytes(Path("/proc") / str(child) / "cmdline").rstrip(b"\0").strip()
        require(title in titles and COMMON.proc_ticks(child) == start, "current_nginx_stable_known_child")
        children[str(child)], roles[str(child)] = start, titles[title]
    require(
        COMMON.proc_ticks(pid) == ticks and any(role == "worker" for role in roles.values()),
        "current_nginx_master_generation_stable",
    )
    return dict(pid=pid, start_ticks=ticks, children=children, child_roles=roles)


def nginx_applied(m, cm, a, evidence, require_live_approval=True):
    """Join actual future apply/input bytes, then read current disk/worker facts.

    APPLY has an immutable one-shot intent. Historical success is not forced to
    reapply after300s; current direct root observations establish fresh identity.
    """
    applied = evidence.get("nginx-apply", "candidate_nginx.py", "web", fresh=False)
    exact(
        applied,
        (
            "schema",
            "runtime_baseline_sha256",
            "baseline_helper_sha256",
            "mode",
            "status",
            "candidate",
            "tree",
            "source",
            "venv",
            "manifest_sha256",
            "helper_sha256",
            "approval_sha256",
            "attempt",
            "started_unix",
            "completed_unix",
            "deployment_ready",
            "observations",
            "evidence",
            "commands",
            "site_sha256",
            "format_sha256",
            "privacy_proven",
            "nginx_master",
            "new_worker_pids",
            "prior_draining_worker_pids",
            "loaded_identity_limit",
            "promotion_manifest_sha256",
            "process_groups",
            "retained_auxiliary_pids",
            "active_catalog_observations",
        ),
    )
    require(
        applied["schema"] == "AcademyNginxReceipt.v3"
        and applied["mode"] == "apply"
        and applied["status"] == "config_applied_new_generation_observed"
        and applied["deployment_ready"] is False
        and applied["privacy_proven"] is False,
        "actual_nginx_apply_result_not_reservation",
    )
    contract = m["nginx_activation"]
    for key in ("candidate", "tree", "source", "venv"):
        require(applied[key] == m[key], "nginx_actual_candidate")
    require(
        applied["runtime_baseline_sha256"] == digest(canonical(COMMON.baseline_runtime(cm, "web")))
        and applied["baseline_helper_sha256"]
        == cm["helpers"]["candidate_baseline.py"]
        == m["producers"]["candidate_baseline.py"]
        and applied["attempt"] == a["attempt"]
        and applied["promotion_manifest_sha256"] == evidence.promotion_manifest_hash
        and applied["helper_sha256"] == cm["helpers"]["candidate_nginx.py"] == contract["helper_sha256"]
        and applied["site_sha256"] == contract["site_sha256"]
        and applied["format_sha256"] == contract["format_sha256"],
        "nginx_actual_static_contract_and_same_promotion",
    )
    descriptor = evidence.value["entries"]["nginx-apply"]
    artifacts = {}
    for name, pin in descriptor["supporting_inputs"].items():
        raw = root_read(pin["path"])
        require(digest(raw) == pin["sha256"], "nginx_actual_supporting_input_bytes")
        artifacts[name] = decode(raw)
    evidence.used["nginx-apply"]["supporting_inputs_sha256"] = {
        name: pin["sha256"] for name, pin in descriptor["supporting_inputs"].items()
    }
    nm, na = artifacts["manifest"], artifacts["approval"]
    exact(
        nm,
        (
            "schema",
            "runtime_baseline",
            "baseline_helper_sha256",
            "candidate",
            "tree",
            "source",
            "venv",
            "self_sha256",
            "plan_sha256",
            "common_path",
            "common_sha256",
            "promoter_path",
            "promoter_sha256",
            "execution_manifest",
            "promotion_manifest",
            "promotion_approval",
            "prepared",
            "assets",
        ),
    )
    require(
        nm["schema"] == "AcademyNginxInputs.v3"
        and canonical(nm["runtime_baseline"])
        == canonical(COMMON.baseline_runtime(cm, "web"))
        == canonical(runtime_for(m, "web"))
        and nm["baseline_helper_sha256"] == cm["helpers"]["candidate_baseline.py"]
        and descriptor["supporting_inputs"]["manifest"]["sha256"] == applied["manifest_sha256"]
        and nm["self_sha256"] == contract["helper_sha256"]
        and nm["common_sha256"] == m["common_sha256"]
        and nm["promoter_sha256"] == m["self_sha256"]
        and nm["execution_manifest"] == m["execution_manifest"]
        and nm["promotion_manifest"]["sha256"] == evidence.promotion_manifest_hash
        and nm["promotion_approval"]["sha256"] == evidence.promotion_approval_hash
        and nm["assets"] == contract["assets"],
        "actual_nginx_manifest_join",
    )
    for key in ("candidate", "tree", "source", "venv"):
        require(nm[key] == m[key], "nginx_manifest_candidate")
    for name in ("promotion_manifest", "promotion_approval"):
        exact(nm[name], ("path", "sha256"))
        require(digest(root_read(nm[name]["path"])) == nm[name]["sha256"], "actual_nginx_promotion_input_bytes")
    exact(nm["prepared"], ("directory", "site_sha256", "format_sha256"))
    require(
        nm["prepared"]["site_sha256"] == contract["site_sha256"]
        and nm["prepared"]["format_sha256"] == contract["format_sha256"],
        "actual_nginx_prepared_static_pins",
    )
    exact(
        na,
        (
            "schema",
            "approved_by",
            "approval_record_path",
            "approval_record_sha256",
            "attempt",
            "approved_unix",
            "expires_unix",
            "manifest_sha256",
            "authorized_modes",
            "benign_privacy_probe",
        ),
    )
    require(
        na["schema"] == "AcademyNginxApproval.v1"
        and na["approved_by"] == "Michael"
        and na["attempt"] == a["attempt"]
        and na["manifest_sha256"] == applied["manifest_sha256"]
        and descriptor["supporting_inputs"]["approval"]["sha256"] == applied["approval_sha256"]
        and digest(root_read(na["approval_record_path"])) == na["approval_record_sha256"],
        "actual_genuine_nginx_approval_bytes",
    )
    require(
        type(na["authorized_modes"]) is list
        and len(set(na["authorized_modes"])) == len(na["authorized_modes"])
        and set(na["authorized_modes"]) <= {"apply", "verify-assets"}
        and "apply" in na["authorized_modes"]
        and type(na["benign_privacy_probe"]) is bool,
        "genuine_nginx_apply_scope",
    )
    require(
        type(na["approved_unix"]) is int
        and type(na["expires_unix"]) is int
        and type(applied["started_unix"]) in {int, float}
        and type(applied["completed_unix"]) in {int, float}
        and na["approved_unix"]
        <= applied["started_unix"]
        <= applied["completed_unix"]
        <= na["expires_unix"]
        <= na["approved_unix"] + 3600
        and applied["completed_unix"] <= time.time(),
        "nginx_actual_apply_authorization_window",
    )
    if require_live_approval:
        require(na["approved_unix"] <= time.time() < na["expires_unix"], "nginx_approval_live_at_web_activation")
    for host_role in ("web", "lab"):
        stop = evidence.phase("quiesce-" + host_role, host_role, "quiesce", fresh=False)
        require(
            applied["started_unix"] >= stop["observations"]["stop_completed_unix"]
            and applied["evidence"]["quiesce-" + host_role]["sha256"]
            == evidence.used["quiesce-" + host_role]["sha256"],
            "nginx_apply_after_both_original_stops",
        )
    keys = ("nginx_before", "nginx_after", "reload", "nginx_expanded_configuration")
    exact(applied["observations"], keys)
    require(
        applied["commands"] == [applied["observations"][key] for key in keys],
        "actual_nginx_syntax_reload_expansion_sequence",
    )
    for command in applied["commands"]:
        exact(command, ("program", "exit_code", "stdout_sha256", "stderr_sha256"))
        require(
            command["program"] == "nginx" and type(command["exit_code"]) is int and command["exit_code"] == 0,
            "actual_nginx_command_exit",
        )
        hexvalue(command["stdout_sha256"])
        hexvalue(command["stderr_sha256"])
    require(
        applied["process_groups"] and all(group.get("confirmed") is True for group in applied["process_groups"]),
        "nginx_owned_command_cleanup",
    )
    require(
        type(applied["active_catalog_observations"]) is list and applied["active_catalog_observations"],
        "actual_nginx_active_catalog_observations",
    )
    expected_input = COMMON.common_input(cm, "web", "candidate_db_readiness.py")
    expected_input.update(
        schema="AcademyCandidateDBReadinessInputs.v4",
        env_sha256=cm["roles"]["web"]["environment_sha256"],
        mode="after",
        database="academy",
        source_file_sha256=cm["db_source_pins"],
        expected_before=cm["expected_before"],
        oidc_expect_empty=True,
    )
    for observed in applied["active_catalog_observations"]:
        exact(
            observed,
            (
                "schema",
                "candidate",
                "tree",
                "attempt",
                "role",
                "migration_history_receipt_sha256",
                "helper_sha256",
                "input_sha256",
                "stdout_sha256",
                "report_sha256",
                "root_launch_started_unix",
                "root_completed_unix",
                "report",
                "both_hosts_stopped_claimed",
                "lab_idle_claimed",
            ),
        )
        require(
            observed["schema"] == "AcademyActiveCatalogObservation.v3"
            and observed["candidate"] == cm["candidate"]
            and observed["tree"] == cm["tree"]
            and observed["attempt"] == a["attempt"]
            and observed["role"] == "web"
            and observed["helper_sha256"] == cm["helpers"]["candidate_db_readiness.py"]
            and observed["input_sha256"] == digest(COMMON.canonical(expected_input))
            and observed["report_sha256"] == digest(COMMON.canonical(observed["report"]))
            and observed["both_hosts_stopped_claimed"] is False
            and observed["lab_idle_claimed"] is False,
            "actual_nginx_active_catalog_provenance",
        )
        verify_catalog_report(observed["report"], cm, "web")
        hexvalue(observed["stdout_sha256"])
        require(
            type(observed["root_launch_started_unix"]) in {int, float}
            and type(observed["root_completed_unix"]) in {int, float}
            and applied["started_unix"] - 1
            <= observed["root_launch_started_unix"]
            <= observed["root_completed_unix"]
            <= applied["completed_unix"],
            "nginx_catalog_actual_original_apply_window",
        )
        COMMON.migration_history(evidence)
        require(
            observed["migration_history_receipt_sha256"] == migration_history_hashes(evidence),
            "nginx_actual_kernel_only_historical_catalog_custody",
        )
    master = applied["nginx_master"]
    exact(master, ("pid", "start_ticks", "children", "child_roles"))
    require(
        type(master["pid"]) is int
        and master["pid"] > 1
        and type(master["start_ticks"]) is str
        and master["start_ticks"].isdigit()
        and type(master["children"]) is dict
        and set(master["children"]) == set(master["child_roles"]),
        "actual_nginx_apply_master",
    )
    require(
        type(applied["new_worker_pids"]) is list
        and applied["new_worker_pids"]
        and len(set(applied["new_worker_pids"])) == len(applied["new_worker_pids"]),
        "actual_nginx_new_worker_generation",
    )
    for pid in applied["new_worker_pids"]:
        require(
            type(pid) is int
            and pid > 1
            and master["child_roles"].get(str(pid)) == "worker"
            and type(master["children"].get(str(pid))) is str
            and master["children"][str(pid)].isdigit(),
            "actual_nginx_new_worker_identity",
        )
    current_read_started = time.time()
    disk = nginx_disk_identity(m)
    current = nginx_live_identity()
    require(
        (current["pid"], current["start_ticks"]) == (master["pid"], master["start_ticks"]),
        "current_nginx_same_applied_master",
    )
    require(
        any(
            current["child_roles"].get(str(pid)) == "worker"
            and current["children"].get(str(pid)) == master["children"][str(pid)]
            for pid in applied["new_worker_pids"]
        ),
        "current_applied_new_generation_accepting_worker",
    )
    return dict(
        apply_result_sha256=evidence.used["nginx-apply"]["sha256"],
        input_manifest_sha256=applied["manifest_sha256"],
        input_approval_sha256=applied["approval_sha256"],
        observed_unix_started=current_read_started,
        observed_unix_finished=time.time(),
        disk=disk,
        master=current,
        public_assets_and_privacy_proven=False,
    )


def paused_timers():
    for timer in COMMON.timers():
        require(state(timer) == dict(MainPID="0", ActiveState="inactive", SubState="dead"), "timers_must_remain_paused")


def verify_catalog_report(report, cm, role):
    COMMON.verify_catalog_readback(report, cm, role, "after")


def migration_history_hashes(evidence):
    """Original immutable receipt hashes; never prehash future evidence."""
    return {
        key: evidence.used[phase]["sha256"]
        for key, phase in (
            ("catalog_before", "db-before"),
            ("kernel_migration", "migrate-kernel0031"),
            ("catalog_after", "db-after"),
        )
    }


def catalog_after(evidence, cm):
    """Historical stopped-phase custody PLUS a distinct fresh readonly catalog.

    Never calls database_phase/both_stopped/fresh_idle and never relabels this
    actual active-runtime query as a stopped db-after receipt.
    """
    COMMON.migration_history(evidence)
    matches = [role for role in ("web", "lab") if cm["roles"][role]["hostname"] == socket.gethostname()]
    require(len(matches) == 1, "active_catalog_actual_validated_host_role")
    role = matches[0]
    value = COMMON.common_input(cm, role, "candidate_db_readiness.py")
    value.update(
        schema="AcademyCandidateDBReadinessInputs.v4",
        env_sha256=cm["roles"][role]["environment_sha256"],
        mode="after",
        database="academy",
        source_file_sha256=cm["db_source_pins"],
        expected_before=cm["expected_before"],
        oidc_expect_empty=True,
    )
    observed = COMMON.helper_call(cm, role, "candidate_db_readiness.py", value)
    verify_catalog_report(observed["report"], cm, role)
    COMMON.stamp(observed["launch_started_unix"])
    require(
        observed["helper_sha256"] == cm["helpers"]["candidate_db_readiness.py"]
        and observed["input_sha256"] == digest(COMMON.canonical(value)),
        "actual_active_catalog_input_and_helper",
    )
    current = dict(
        schema="AcademyActiveCatalogObservation.v3",
        candidate=cm["candidate"],
        tree=cm["tree"],
        attempt=evidence.a["attempt"],
        role=role,
        migration_history_receipt_sha256=migration_history_hashes(evidence),
        helper_sha256=observed["helper_sha256"],
        input_sha256=observed["input_sha256"],
        stdout_sha256=observed["stdout_sha256"],
        report_sha256=digest(COMMON.canonical(observed["report"])),
        root_launch_started_unix=observed["launch_started_unix"],
        root_completed_unix=int(time.time()),
        report=observed["report"],
        both_hosts_stopped_claimed=False,
        lab_idle_claimed=False,
    )
    evidence.active_catalog_observations.append(current)
    return current


def fresh_other_process(role, m, cm, a, evidence):
    promoted = evidence.promoted(role)
    report = evidence.get("process-" + role, "candidate_process_observer.py", role)
    process_report(report, m, cm, a, role)
    original = promoted["observations"]["process"]["report"]
    require(
        report["pid"] == original["pid"]
        and report["start_ticks"] == original["start_ticks"]
        and report["import_environment_sha256"] == original["import_environment_sha256"],
        "current_same_new_process",
    )
    return report


def promote(role, m, cm, a, evidence, progress):
    observer_path(m)  # Provisioning must exist before any override write/start.
    staged = COMMON.verify_stage(cm, role, evidence)
    catalog = catalog_after(evidence, cm)
    COMMON.exclusion(evidence, cm, a, role, "adopted_and_fenced" if role == "lab" else "fenced")
    held = held_gate(role, m, cm, a, evidence)
    if role == "lab":
        COMMON.both_stopped(evidence, role, cm)
        idle = COMMON.fresh_idle(cm, role, "after", a["attempt"])
    else:
        fresh_other_process("lab", m, cm, a, evidence)
        COMMON.stopped("web", cm)
        paused_timers()
        idle = COMMON.fresh_idle(cm, role, "after", a["attempt"])
    targets = m["roles"][role]["units"]
    # Validate every unit, configured argument, environment and render hash
    # before creating the first directory or file.
    proposals = [unit_proposal(unit, targets[unit], m, role) for unit in units(role)]
    for proposal in proposals:
        path = dropin_path(proposal["unit"], m)
        require(not path.exists() and not path.is_symlink(), "fresh_dropin_only_no_overwrite")
    COMMON.preserved(role, cm)
    held_gate(role, m, cm, a, evidence)
    catalog_after(evidence, cm)
    nginx = nginx_applied(m, cm, a, evidence) if role == "web" else None
    for proposal in proposals:
        progress.setdefault("override_write_attempted", []).append(
            {"unit": proposal["unit"], "sha256": digest(proposal["text"].encode())}
        )
        write_override(proposal, m)
        progress.setdefault("overrides_written", []).append(proposal["unit"])
    progress["daemon_reload_attempted"] = True
    systemctl("daemon-reload")
    progress["daemon_reload_completed"] = True
    environments = {unit: validate_new_unit(unit, targets[unit], m, role) for unit in units(role)}
    require(
        digest(
            canonical(
                {
                    u: digest(canonical({k: digest(v.encode()) for k, v in env.items()}))
                    for u, env in environments.items()
                }
            )
        )
        == m["roles"][role]["effective_environment_sha256"],
        "all_effective_environment_inventory",
    )
    COMMON.preserved(role, cm)
    held_gate(role, m, cm, a, evidence)
    catalog_after(evidence, cm)
    approval_live()
    if role == "web":
        nginx = nginx_applied(m, cm, a, evidence)
    progress["candidate_start_attempted"] = units(role)[0]
    systemctl("start", [units(role)[0]])
    deadline = time.monotonic() + 30
    while state(units(role)[0])["ActiveState"] == "activating":
        require(time.monotonic() < deadline, "candidate_start_timeout")
        time.sleep(0.2)
    identity = new_process(role, m, cm, environments[units(role)[0]])
    progress["started_candidate_identity"] = identity
    process = observe_process(role, m, cm, a, identity)
    require(
        new_process(role, m, cm, environments[units(role)[0]]) == identity, "candidate_process_changed_during_proof"
    )
    if role == "web":
        paused_timers()
        for unit in units(role)[1:]:
            require(
                state(unit) == dict(MainPID="0", ActiveState="inactive", SubState="dead"), "web_cli_remains_inactive"
            )
    return dict(
        stage=staged,
        historical_db_after_receipt_sha256=catalog["migration_history_receipt_sha256"]["catalog_after"],
        active_catalog_observations=list(evidence.active_catalog_observations),
        idle_before=idle,
        gate=held,
        override_sha256={p["unit"]: digest(p["text"].encode()) for p in proposals},
        identity=identity,
        process=process,
        preserved=COMMON.preserved(role, cm),
        timers_paused=True,
        nginx_activation=nginx,
    )


def stop_new(role, m, cm, a, evidence):
    if role == "web":
        paused_timers()
        for unit in units(role)[1:]:
            require(
                state(unit) == dict(MainPID="0", ActiveState="inactive", SubState="dead"),
                "unexpected_cli_requires_manual_hold",
            )
    observed = stop_owned_candidate(role, m, cm)
    nginx = nginx_disk_identity(m) if role == "web" else None
    return dict(
        stopped=observed["stopped"],
        nginx_config_preserved=nginx,
        stopped_identity=observed["identity"],
        preserved=COMMON.preserved(role, cm),
        timers_paused=True,
        old_restart_performed=False,
    )


def acceptance(m, cm, a, evidence, *, resumed=False):
    # A web consumer validates retained Lab custody; only an actual Lab
    # boundary independently checks current Lab systemd/process state.
    COMMON.maintenance_module(cm).verify_retained(COMMON, cm, evidence, a, "lab", "adopted_and_fenced")
    report = evidence.get("acceptance-cleanup", "acceptance_observer", "web")
    exact(
        report,
        (
            "schema",
            "candidate",
            "tree",
            "attempt",
            "hostname",
            "observed_unix_started",
            "hold_id",
            "owner_record_sha256",
            "runtime_processes",
            "scopes",
            "owned_cleanup",
            "mail_cleanup_sha256",
            "maintenance_lab_boundary",
        ),
    )
    require(
        report["schema"] == "AcademyCandidateAcceptanceCleanup.v1"
        and report["candidate"] == m["candidate"]
        and report["tree"] == m["tree"]
        and report["attempt"] == a["attempt"]
        and report["hostname"] == cm["roles"]["web"]["hostname"],
        "acceptance_candidate_attempt",
    )
    stamp(report["observed_unix_started"])
    pin = report["maintenance_lab_boundary"]
    exact(pin, ("path", "sha256"))
    raw = root_read(pin["path"], limit=100000000)
    hexvalue(pin["sha256"])
    require(digest(raw) == pin["sha256"], "actual_lab_boundary_bytes")
    boundary = decode(raw)
    require(
        boundary["schema"] == "AcademyAcceptanceBoundaryObservation.v1" and boundary["role"] == "lab",
        "actual_lab_acceptance_boundary",
    )
    for key in ("candidate", "tree", "source", "venv", "attempt"):
        require(boundary["binding"][key] == (a[key] if key == "attempt" else cm[key]), "lab_boundary_identity")
    authority = boundary["maintenance_authority"]
    exact(
        authority,
        ("execution_manifest_sha256", "component_sha256", "helper_sha256", "promotion_approval_sha256", "guard_sha256"),
    )
    require(
        authority["execution_manifest_sha256"] == evidence.manifest_hash
        and authority["component_sha256"] == cm["maintenance"]["sha256"]
        and authority["helper_sha256"] == cm["helpers"]["maintenance"]["sha256"]
        and authority["promotion_approval_sha256"] == evidence.promotion_approval_hash,
        "lab_boundary_actual_authority",
    )
    acceptance_pin = boundary["acceptance_manifest"]
    exact(acceptance_pin, ("path", "sha256"))
    acceptance_raw = root_read(acceptance_pin["path"])
    require(
        digest(acceptance_raw) == acceptance_pin["sha256"] == boundary["binding"]["acceptance_manifest_sha256"],
        "lab_boundary_acceptance_manifest",
    )
    acceptance_manifest = decode(acceptance_raw)
    require(
        acceptance_manifest["schema"] == "AcademyAcceptanceBinding.v3"
        and acceptance_manifest["execution_manifest"] == m["execution_manifest"]
        and acceptance_manifest["tool_sha256"]["guard.py"] == authority["guard_sha256"],
        "lab_boundary_reviewed_guard_binding",
    )
    approval_pin = boundary["acceptance_approval"]
    exact(approval_pin, ("path", "sha256"))
    approval_raw = root_read(approval_pin["path"])
    require(
        digest(approval_raw) == approval_pin["sha256"] == boundary["binding"]["approval_sha256"],
        "lab_boundary_acceptance_approval_bytes",
    )
    accepted_approval = decode(approval_raw)
    require(
        accepted_approval["schema"] == "AcademyAcceptanceApproval.v1"
        and accepted_approval["approved_by"] == "Michael"
        and accepted_approval["manifest_sha256"] == acceptance_pin["sha256"]
        and accepted_approval["attempt"] == a["attempt"]
        and boundary["phase"] in accepted_approval["authorized_phases"]
        and accepted_approval["approved_unix"] <= boundary["completed_unix"] < accepted_approval["expires_unix"],
        "lab_boundary_genuine_approval_window",
    )
    human = accepted_approval["approval_record"]
    exact(human, ("path", "sha256"))
    require(digest(root_read(human["path"])) == human["sha256"], "lab_boundary_actual_human_record")
    stamp(boundary["completed_unix"])
    require(boundary["completed_unix"] <= report["observed_unix_started"], "cleanup_after_lab_boundary")
    require(
        boundary["evidence"]["maintenance-lab-adopted_and_fenced"]["sha256"]
        == evidence.used["maintenance-lab-adopted_and_fenced"]["sha256"],
        "cleanup_actual_lab_maintenance_join",
    )
    require(all(x["confirmed"] is True for x in boundary["process_groups"]), "lab_boundary_process_cleanup")
    exact(report["runtime_processes"], ("web", "lab"))
    for role in ("web", "lab"):
        current = fresh_other_process(role, m, cm, a, evidence)
        exact(report["runtime_processes"][role], ("pid", "start_ticks"))
        require(
            report["runtime_processes"][role] == {k: current[k] for k in ("pid", "start_ticks")},
            "acceptance_exact_new_process",
        )
    exact(report["scopes"], ("delivery_resend", "routeros", "linux_ttyd", "admissions", "logging"))
    for item in report["scopes"].values():
        exact(item, ("result", "proof_path", "proof_sha256"))
        require(
            item["result"] == "passed"
            and digest(root_read(item["proof_path"], limit=100000000)) == item["proof_sha256"],
            "actual_acceptance_proof_bytes",
        )
    cleanup = report["owned_cleanup"]
    exact(
        cleanup,
        (
            "remaining_owned_active_actors",
            "remaining_owned_grants",
            "remaining_owned_active_enrollments",
            "remaining_owned_deliverable_mail",
            "remaining_owned_runtimes",
            "unknown_ownership",
            "retained_applicant_rows",
            "retained_audit_rows",
            "retained_suspended_actor_rows",
            "retained_dropped_enrollment_rows",
            "retained_revoked_grant_rows",
            "cleanup_proof_path",
            "cleanup_proof_sha256",
        ),
    )
    retained = {
        "retained_applicant_rows",
        "retained_audit_rows",
        "retained_suspended_actor_rows",
        "retained_dropped_enrollment_rows",
        "retained_revoked_grant_rows",
    }
    for key in retained:
        require(type(cleanup[key]) is int and cleanup[key] >= 0, "retained_semantic_row_counts")
    for key in set(cleanup) - retained - {"cleanup_proof_path", "cleanup_proof_sha256"}:
        require(type(cleanup[key]) is int and cleanup[key] == 0, "owned_active_authority_cleanup_not_zero")
    require(
        digest(root_read(cleanup["cleanup_proof_path"], limit=100000000)) == cleanup["cleanup_proof_sha256"],
        "actual_owned_cleanup_proof",
    )
    for key in ("hold_id", "owner_record_sha256", "mail_cleanup_sha256"):
        hexvalue(report[key])
    return report


def released_gate(m, cm, a, evidence, accepted):
    completed = evidence.get("release-completed", "mail_hold_operator.py", "web")
    exact(
        completed,
        (
            "schema",
            "status",
            "candidate",
            "tree",
            "hostname",
            "hold_id",
            "owner_record_sha256",
            "approval_sha256",
            "cleanup_sha256",
            "supervisor_pid",
            "supervisor_start_ticks",
            "hold_ready_at",
            "lock_inode",
            "state_sha256",
            "observed_at",
            "external_post_release_verification_required",
        ),
    )
    require(
        completed["schema"] == "AcademyMailReleaseCompleted.v1"
        and completed["status"] == "release_completed"
        and completed["candidate"] == m["candidate"]
        and completed["tree"] == m["tree"]
        and completed["hostname"] == cm["roles"]["web"]["hostname"]
        and completed["hold_id"] == accepted["hold_id"]
        and completed["owner_record_sha256"] == accepted["owner_record_sha256"]
        and completed["cleanup_sha256"] == accepted["mail_cleanup_sha256"]
        and completed["state_sha256"] == digest(b"OPEN\n"),
        "actual_release_completed",
    )
    base = Path("/var/lib/dotmac-academy/mail-delivery")
    owner_raw = root_read(base / "owner.json", private=False, mode=0o600)
    owner = decode(owner_raw)
    claim = decode(root_read(base / "supervisor-claim.json", private=False, mode=0o600))
    require(
        digest(owner_raw) == completed["owner_record_sha256"]
        and owner["hold_id"] == owner["epoch"] == completed["hold_id"]
        and owner["approval_sha256"] == claim["approval_sha256"] == completed["approval_sha256"]
        and owner["script_sha256"] == cm["helpers"]["mail_hold_operator.py"]
        and owner["plan_sha256"] == cm["gate_plan_sha256"],
        "same_gate_owner_epoch_approval_history",
    )
    require(
        claim["owner_record_sha256"] == completed["owner_record_sha256"]
        and claim["supervisor_pid"] == completed["supervisor_pid"]
        and str(claim["supervisor_start_ticks"]) == str(completed["supervisor_start_ticks"]),
        "release_supervisor_history",
    )
    require(root_read(base / "state", private=False, mode=0o644) == b"OPEN\n", "actual_live_gate_open")
    parent = root_directory(base)
    try:
        info = os.stat("lock", dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISREG(info.st_mode) and info.st_uid == 0 and [info.st_dev, info.st_ino] == completed["lock_inode"],
            "same_released_gate_inode",
        )
    finally:
        os.close(parent)
    stamp(COMMON.datetime.fromisoformat(completed["observed_at"].replace("Z", "+00:00")).timestamp())
    return completed


def resume(role, m, cm, a, evidence, progress):
    if role == "lab":
        return verify_completion(m, cm, a, evidence)
    require(role == "web", "resume_web_only")
    nginx = nginx_applied(m, cm, a, evidence)
    accepted = acceptance(m, cm, a, evidence)
    released = released_gate(m, cm, a, evidence, accepted)
    progress["gate_was_open_no_automatic_rehold"] = True
    paused_timers()
    environments = {u: validate_new_unit(u, m["roles"][role]["units"][u], m, role) for u in units(role)}
    new_process(role, m, cm, environments[units(role)[0]])
    COMMON.preserved(role, cm)
    baseline = evidence.phase("baseline-web", "web", "baseline", fresh=False)
    original = baseline["observations"]["baseline"]["timers"]
    require(set(original) == set(COMMON.timers()), "original_active_baseline_timer_set")
    for timer in original:
        require(original[timer] == cm["roles"]["web"]["baseline"]["timers"][timer], "original_timer_identity")
        current = properties(timer, "ActiveState,UnitFileState,Unit")
        require(current["ActiveState"] == "inactive", "timer_inactive_before_resume")
        current["ActiveState"] = "active"  # Compare original config, not recapture.
        require(
            digest(canonical(current)) == original[timer]["properties_sha256"]
            and digest(systemctl("cat", [timer]).encode()) == original[timer]["unit_sha256"],
            "original_timer_configuration_unchanged",
        )
        nginx_disk_identity(m)
        progress["started_timers"].append(timer)  # Before start: failed start may still act.
        systemctl("start", [timer])
        value = state(timer)
        require(
            value["ActiveState"] == "active" and value["SubState"] in {"waiting", "elapsed", "running"},
            "resumed_timer_state",
        )
    released_gate(m, cm, a, evidence, accepted)
    fresh_other_process("lab", m, cm, a, evidence)
    new_process(role, m, cm, environments[units(role)[0]])
    return dict(
        operational_complete=False,
        maintenance_lab_resume_required=True,
        nginx_activation=nginx,
        nginx_config_preserved=nginx_disk_identity(m),
        resumed_original_timers=list(original),
        gate_release_sha256=evidence.used["release-completed"]["sha256"],
        acceptance_cleanup_sha256=evidence.used["acceptance-cleanup"]["sha256"],
        gate_open_confirmed=True,
        legacy_retained=True,
        release=released,
    )


def verify_web_resume_custody(m, cm, a, evidence):
    """Validate retained actual web release/resume without reading a Lab-local gate."""
    web = evidence.get("resumed-web", "candidate_promote.py", "web")
    require(
        web["schema"] == "AcademyPromotionReceipt.v1"
        and web["status"] == "observed"
        and web["phase"] == "resume"
        and web["role"] == "web"
        and web["manifest_sha256"] == evidence.promotion_manifest_hash
        and web["approval_sha256"] == evidence.promotion_approval_hash
        and web["deployment_ready"] is False,
        "genuine_web_resume_receipt",
    )
    for key in ("candidate", "tree", "attempt"):
        require(web[key] == (a[key] if key == "attempt" else cm[key]), "web_resume_identity")
    require(all(x["confirmed"] is True for x in web["process_groups"]), "web_resume_process_cleanup")
    stamp(web["completed_unix"])
    require(
        set(web["observations"]["resumed_original_timers"]) == set(COMMON.timers())
        and web["observations"]["gate_open_confirmed"] is True,
        "actual_web_timer_resume",
    )
    accepted = acceptance(m, cm, a, evidence, resumed=True)
    released = evidence.get("release-completed", "mail_hold_operator.py", "web")
    require(
        released == web["observations"]["release"]
        and evidence.used["release-completed"]["sha256"] == web["observations"]["gate_release_sha256"]
        and evidence.used["acceptance-cleanup"]["sha256"] == web["observations"]["acceptance_cleanup_sha256"]
        and released["cleanup_sha256"] == accepted["mail_cleanup_sha256"],
        "web_actual_gate_release_and_cleanup_join",
    )
    stamp(COMMON.datetime.fromisoformat(released["observed_at"].replace("Z", "+00:00")).timestamp())
    released_at = COMMON.datetime.fromisoformat(released["observed_at"].replace("Z", "+00:00")).timestamp()
    require(released_at <= web["completed_unix"] <= time.time(), "release_before_web_resume")
    return dict(web_receipt=web, acceptance=accepted, release=released, release_time=released_at)


def verify_completion(m, cm, a, evidence):
    """resume --role lab is VERIFY-ONLY; standalone maintenance owns Lab changes."""
    custody = verify_web_resume_custody(m, cm, a, evidence)
    web, accepted, released = custody["web_receipt"], custody["acceptance"], custody["release"]
    released_at = custody["release_time"]
    maintenance = COMMON.maintenance_observation(cm, evidence, a, "lab", "resumed")
    resumed_lab = evidence.get("maintenance-lab-resumed", "candidate_maintenance.py", "lab")
    require(
        released_at
        <= web["completed_unix"]
        <= resumed_lab["observed_unix_started"]
        <= resumed_lab["observed_unix_finished"]
        <= time.time(),
        "release_web_resume_lab_resume_final_chronology",
    )
    catalog = catalog_after(evidence, cm)
    process = fresh_other_process("lab", m, cm, a, evidence)
    COMMON.preserved("lab", cm)
    return dict(
        operational_complete=True,
        web_resume_sha256=evidence.used["resumed-web"]["sha256"],
        maintenance_lab_resumed=maintenance,
        acceptance=accepted,
        release=released,
        catalog=catalog,
        process=process,
        verify_only=True,
        web_live_gate_proven_by_resume_receipt=True,
    )


def resume_failure(progress):
    outcome = dict(
        stopped_started_timers=False, cli_drain_confirmed=False, gate_reheld=False, manual_fix_forward_hold=True
    )
    try:
        if progress["started_timers"]:
            systemctl("stop", progress["started_timers"], cleanup=True)
        outcome["stopped_started_timers"] = all(
            state(t) == dict(MainPID="0", ActiveState="inactive", SubState="dead") for t in progress["started_timers"]
        )
        deadline = time.monotonic() + 60
        while True:
            if all(state(u) == dict(MainPID="0", ActiveState="inactive", SubState="dead") for u in units("web")[1:]):
                outcome["cli_drain_confirmed"] = True
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(1)
    except BaseException:
        outcome["cleanup_unconfirmed"] = True
    return outcome


def main():
    global COMMON, ACTIVE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--role", choices=("web", "lab"), required=True)
    for key in ("manifest", "approval", "evidence-index", "receipt"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    require(
        sys.platform == "linux" and os.getuid() == os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site,
        "trusted_linux_root_I_S",
    )
    m, manifest_hash = load(args.manifest)
    require(type(m) is dict and "common_path" in m and "common_sha256" in m, "bootstrap_common_pin")
    COMMON = load_common(m["common_path"], m["common_sha256"])
    validate_manifest(m, args.role)
    COMMON.host_execution_lock()
    cm, execution_manifest_hash = load(m["execution_manifest"]["path"])
    require(
        execution_manifest_hash == m["execution_manifest"]["sha256"] and cm["self_sha256"] == m["common_sha256"],
        "frozen_common_manifest",
    )
    require(
        digest(root_read(Path(m["execution_manifest"]["path"]).parent / "execution-plan.json")) == cm["plan_sha256"],
        "actual_reviewed_execution_plan",
    )
    COMMON.validate_manifest(cm, args.role)
    require(
        m["producers"]["candidate_baseline.py"] == cm["helpers"]["candidate_baseline.py"], "shared_baseline_helper_join"
    )
    for host_role in ("web", "lab"):
        observed_runtime = COMMON.baseline_runtime(cm, host_role)
        require(
            canonical(m["roles"][host_role]["runtime_baseline"]) == canonical(observed_runtime),
            "identical_role_runtime_baseline",
        )
    for key in ("candidate", "tree", "source", "venv", "previous", "recovery", "retention"):
        require(m[key] == cm[key], "same_frozen_execution_candidate")
    COMMON.SOURCE, COMMON.VENV = m["source"], m["venv"]
    require(
        digest(root_read(Path(__file__).absolute())) == m["self_sha256"]
        and digest(root_read(Path(args.manifest).parent / "promotion-plan.json")) == m["plan_sha256"],
        "promoter_plan_hash",
    )
    a, approval_hash = load(args.approval)
    authorization(a, m, manifest_hash, args.phase)
    evidence = Evidence(args.evidence_index, m, cm, a, approval_hash, manifest_hash, execution_manifest_hash)
    evidence.active_authority = {
        "kind": "promotion",
        "phase": args.phase,
        "manifest": {"path": args.manifest, "sha256": manifest_hash},
        "approval": {"path": args.approval, "sha256": approval_hash},
    }
    evidence.validate_active_authority = lambda current, manifest, sha256, phase: authorization(
        current, manifest, sha256, phase
    )
    for sig in COMMON.INTERRUPTS:
        signal.signal(sig, COMMON.interrupt_stage)
    receipt = Path(args.receipt)
    require(
        receipt.parent == Path(args.manifest).parent and re.fullmatch(r"[a-z0-9-]+\.json", receipt.name),
        "receipt_namespace",
    )
    intent_path = receipt.parent / ("promotion-intent-" + m["candidate"] + "-" + args.role + "-" + args.phase + ".json")
    intent = dict(
        schema="AcademyPromotionIntent.v1",
        candidate=m["candidate"],
        tree=m["tree"],
        role=args.role,
        phase=args.phase,
        attempt=a["attempt"],
        manifest_sha256=manifest_hash,
        approval_sha256=approval_hash,
        evidence_index_sha256=evidence.sha256,
        evidence=evidence.value["entries"],
        started_unix=int(time.time()),
        recovery=m["recovery"],
        retention=m["retention"],
    )
    COMMON.write_new(
        receipt,
        dict(
            schema="AcademyPromotionReservation.v1",
            status="started_or_interrupted_hold",
            candidate=m["candidate"],
            attempt=a["attempt"],
            phase=args.phase,
            intent=intent_path.name,
        ),
    )
    COMMON.write_new(intent_path, intent)
    result = dict(
        schema="AcademyPromotionReceipt.v1",
        status="failed_fix_forward_manual_hold",
        candidate=m["candidate"],
        tree=m["tree"],
        role=args.role,
        phase=args.phase,
        attempt=a["attempt"],
        manifest_sha256=manifest_hash,
        approval_sha256=approval_hash,
        evidence_index_sha256=evidence.sha256,
        intent_sha256=digest(canonical(intent) + b"\n"),
        started_unix=intent["started_unix"],
        completed_unix=0,
        evidence={},
        observations={},
        process_groups=[],
        deployment_ready=False,
    )
    progress = dict(started_timers=[], gate_was_open_no_automatic_rehold=False)
    ACTIVE = dict(
        manifest=m,
        approval=a,
        role=args.role,
        phase=args.phase,
        directory=receipt.parent,
        manifest_sha256=manifest_hash,
        approval_sha256=approval_hash,
        intent_sha256=result["intent_sha256"],
        progress=progress,
    )
    try:
        if args.phase == "promote":
            result["observations"] = promote(args.role, m, cm, a, evidence, progress)
        elif args.phase == "stop-new":
            result["observations"] = stop_new(args.role, m, cm, a, evidence)
        else:
            result["observations"] = resume(args.role, m, cm, a, evidence, progress)
        require(all(x["confirmed"] is True for x in COMMON.PROCESS_GROUPS), "owned_process_cleanup")
        result["status"] = "observed"
    except BaseException:
        result["observations"]["partial_operation"] = progress
        if args.phase == "promote" and progress.get("candidate_start_attempted"):
            for sig in COMMON.INTERRUPTS:
                signal.signal(sig, signal.SIG_IGN)
            cleanup = failed_start_cleanup(args.role, m, cm, a, evidence)
            result["observations"]["failed_start_cleanup"] = cleanup
            result["status"] = (
                "failed_candidate_stopped_fix_forward_hold"
                if cleanup["confirmed"]
                else "candidate_ownership_or_cleanup_unconfirmed_manual_hold"
            )
        if args.phase == "stop-new":
            result["status"] = "candidate_stop_unconfirmed_manual_hold"
        if args.phase == "resume" and args.role == "web":
            for sig in COMMON.INTERRUPTS:
                signal.signal(sig, signal.SIG_IGN)
            result["observations"]["partial_resume_cleanup"] = resume_failure(progress)
        raise
    finally:
        for sig in COMMON.INTERRUPTS:
            signal.signal(sig, signal.SIG_IGN)
        result["observations"].setdefault("active_catalog_observations", list(evidence.active_catalog_observations))
        result.update(completed_unix=int(time.time()), evidence=evidence.used, process_groups=COMMON.PROCESS_GROUPS)
        if any(not x.get("confirmed") for x in COMMON.PROCESS_GROUPS):
            result["status"] = "process_cleanup_unconfirmed_manual_hold"
        COMMON.write_new(receipt.with_name(receipt.stem + "-result.json"), result)
    print(
        json.dumps(
            dict(
                status=result["status"],
                phase=args.phase,
                receipt_sha256=digest(canonical(result) + b"\n"),
                deployment_ready=False,
            )
        )
    )


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print(
            '{"status":"refused_or_failed_fix_forward_hold","details":"preserve_all_intents_partial_overrides_receipts_and_gate_history","deployment_ready":false}'
        )
        sys.exit(1)
