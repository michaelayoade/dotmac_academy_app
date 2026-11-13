#!/usr/bin/env python3
"""Prepared-only source: root-local exact Academy static/logging activation.

No SSH, approval creation, legacy restore, application import or package install.
Run only after independent review with genuine frozen inputs: python3 -I -S.
"""

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import types
import zipfile
from pathlib import Path

SITE = Path("/etc/nginx/sites-enabled/academy")
FORMAT = Path("/etc/nginx/conf.d/academy-candidate-path-only.conf")
LOG = Path("/var/log/nginx/academy_access.log")
HISTORICAL_SITE_SHA256 = "e8229f09f31805f77bbead05d6f3332d38baf5fe45878cb06d80fcb4faf7b7b6"
FORMAT_BYTES = (
    b"# Academy method/path metadata only; excludes query and referrer.\n"
    b"log_format academy_candidate_path_only '$remote_addr [$time_local] "
    b'"$request_method $uri $server_protocol" '
    b"$status $body_bytes_sent $request_time';\n"
)
ACCESS = b"access_log /var/log/nginx/academy_access.log academy_candidate_path_only;"
URLS = (
    "/static/academy.js",
    "/static/lifecycle.js",
    "/static/css/toasts.css",
    "/static/css/main.css",
    "/static/js/components.js",
    "/static/js/alpine.min.js",
)
COMMON = PROMOTER = None
AUTH = None
COMMANDS = []
PREVIOUS_SIGNALS = {}


def require(ok, label):
    if not ok:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite_json"))


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), "strict_fields")


def hexhash(value, size=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value), "hash")


def directory(path, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute_directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "root_directory")
        require(not private or (path.parts[1] == "root" and not os.fstat(fd).st_mode & 0o077), "private_directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, private=True, limit=16000000, mode=None):
    path = Path(path)
    parent = directory(path.parent, private)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1
                and not before.st_mode & 0o022
                and before.st_size <= limit,
                "root_single_link_file",
            )
            require(not private or not before.st_mode & 0o077, "private_file")
            require(mode is None or stat.S_IMODE(before.st_mode) == mode, "file_mode")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            require(
                len(raw) <= limit
                and (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "stable_read",
            )
            return raw
    finally:
        os.close(parent)


def load(path):
    raw = read(path)
    return decode(raw), sha(raw)


def live():
    require(
        AUTH is not None and AUTH["approved_unix"] <= time.time() < AUTH["expires_unix"],
        "approval_expired_before_mutation",
    )


def fresh(path, raw, mode=0o600, authorized=False, private=True):
    path = Path(path)
    parent = directory(path.parent, private)
    try:
        if authorized:
            live()
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent
        )
        try:
            info = os.fstat(fd)
            require(info.st_uid == 0 and info.st_nlink == 1 and stat.S_ISREG(info.st_mode), "fresh_file")
            if authorized:
                live()
            os.fchmod(fd, mode)
            with os.fdopen(os.dup(fd), "wb") as stream:
                if authorized:
                    live()
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def module(path, expected, basename):
    require(Path(path).name == basename, "reviewed_module_name")
    raw = read(path)
    require(sha(raw) == expected, "reviewed_module_hash")
    value = types.ModuleType("reviewed_" + basename.replace(".", "_"))
    value.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), value.__dict__)  # noqa: S102 -- exact reviewed root-private stdlib source
    return value


def runtime_baseline(m):
    helper = COMMON.baseline_module({"helpers": {"candidate_baseline.py": m["baseline_helper_sha256"]}})
    return helper.validate_runtime(m["runtime_baseline"], "web", COMMON.pwd.getpwnam("dotmac").pw_uid)


def nodes(raw):
    """Conservative Nginx lexer: byte spans, quoted tokens and comments preserved."""
    tokens = list(
        re.finditer(rb"""\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|(?:\\[^\r\n]|[^\s{};#'"\\])+""", raw)
    )
    require(b"".join(t.group() for t in tokens) == raw, "unsupported_nginx_lexeme")
    useful = [t for t in tokens if not t.group().isspace() and not t.group().startswith(b"#")]
    index = 0

    def parse(nested=False):
        nonlocal index
        result = []
        while index < len(useful):
            first = useful[index]
            if first.group() == b"}":
                require(nested, "unexpected_close")
                index += 1
                return result, first.end()
            words = []
            while index < len(useful) and useful[index].group() not in (b"{", b"}", b";"):
                words.append(useful[index].group())
                index += 1
            require(words and index < len(useful), "incomplete_directive")
            end = useful[index]
            index += 1
            if end.group() == b"{":
                children, finish = parse(True)
            else:
                require(end.group() == b";", "expected_semicolon")
                children, finish = None, end.end()
            result.append(dict(words=words, start=first.start(), end=finish, children=children))
        require(not nested, "unclosed_block")
        return result, len(raw)

    return parse()[0]


def transform(original, source, old_source):
    top = nodes(original)
    servers = [
        n
        for n in top
        if n["words"] == [b"server"]
        and n["children"] is not None
        and any(c["words"] == [b"server_name", b"academy.dotmac.io"] for c in n["children"])
    ]
    require(len(servers) == 2, "exact_two_academy_servers")
    tls = [n for n in servers if any(c["words"][0] == b"listen" and b"ssl" in c["words"] for c in n["children"])]
    require(len(tls) == 1, "exact_academy_tls_server")
    children = tls[0]["children"]
    static = [n for n in children if n["words"] == [b"location", b"/static/"]]
    proxy = [n for n in children if n["words"] == [b"location", b"/"]]
    require(len(static) == len(proxy) == 1, "exact_static_and_root_locations")
    require(not any(b"@academy_static" in n["words"] for n in children), "fresh_named_location")
    roots = [n for n in static[0]["children"] if n["words"][0] == b"root"]
    require(len(roots) == 1 and roots[0]["words"] == [b"root", old_source.encode()], "exact_old_static_root")
    require(
        not any(n["words"][0] in (b"try_files", b"alias") for n in static[0]["children"]),
        "static_no_existing_fallback_or_log_override",
    )
    require(
        any(n["words"] == [b"proxy_pass", b"http://127.0.0.1:8002"] for n in proxy[0]["children"]),
        "existing_exact_loopback_proxy",
    )
    forward = [n for n in proxy[0]["children"] if n["words"][0] == b"proxy_set_header"]
    expected = {
        b"Host": b"$host",
        b"X-Real-IP": b"$remote_addr",
        b"X-Forwarded-For": b"$proxy_add_x_forwarded_for",
        b"X-Forwarded-Proto": b"$scheme",
    }
    require(all(n["children"] is None and len(n["words"]) == 3 for n in forward), "literal_forward_headers")
    actual = {n["words"][1]: n["words"][2] for n in forward}
    require(len(actual) == len(forward) and actual == expected, "supported_exact_forward_headers")
    # Copy exact original directive bytes, preserving forwarded identity semantics.
    directives = [n for n in proxy[0]["children"] if n["words"][0] in (b"proxy_pass", b"proxy_set_header")]
    require(sum(n["words"][0] == b"proxy_pass" for n in directives) == 1, "single_upstream")
    edits = [
        (roots[0]["start"], roots[0]["end"], b"root " + source.encode() + b";\n        try_files $uri @academy_static;")
    ]
    block = (
        b"\n    location @academy_static {\n"
        + b"".join(b"        " + original[n["start"] : n["end"]] + b"\n" for n in directives)
        + b"    }\n"
    )
    edits.append((static[0]["end"], static[0]["end"], block))
    for server in servers:
        require(not any(c["words"][0] == b"access_log" for c in server["children"]), "no_existing_server_access_log")

        def check_logs(items):
            for node in items:
                require(
                    node["words"][0] != b"access_log" or node["words"] == [b"access_log", b"off"],
                    "no_nested_access_log_override",
                )
                if node["children"] is not None:
                    check_logs(node["children"])

        check_logs(server["children"])
        anchor = next(c for c in server["children"] if c["words"] == [b"server_name", b"academy.dotmac.io"])
        edits.append((anchor["end"], anchor["end"], b"\n    " + ACCESS))
    result = original
    for start, end, replacement in sorted(edits, reverse=True):
        result = result[:start] + replacement + result[end:]
    nodes(result)
    # Every byte outside the explicit spans above is preserved, including figures,
    # console upstreams, TLS directives and other virtual hosts.
    return result


def validate_manifest(m, mode):
    if mode == "prepare":
        exact(
            m,
            (
                "schema",
                "candidate",
                "source",
                "self_sha256",
                "plan_sha256",
                "common_path",
                "common_sha256",
                "prepared",
                "runtime_baseline",
                "baseline_helper_sha256",
            ),
        )
        require(m["schema"] == "AcademyNginxPrepareInputs.v2", "independent_prepare_schema")
        hexhash(m["candidate"], 40)
        require(m["source"] == "/srv/academy/releases/" + m["candidate"], "prepare_source_namespace")
        for key in ("self_sha256", "plan_sha256", "common_sha256", "baseline_helper_sha256"):
            hexhash(m[key])
        exact(m["prepared"], ("directory", "site_sha256", "format_sha256"))
        require(
            m["prepared"]["site_sha256"] is None and m["prepared"]["format_sha256"] == sha(FORMAT_BYTES),
            "prepare_expected_format",
        )
        return
    exact(
        m,
        (
            "schema",
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
            "runtime_baseline",
            "baseline_helper_sha256",
        ),
    )
    require(m["schema"] == "AcademyNginxInputs.v3", "manifest_schema")
    hexhash(m["candidate"], 40)
    hexhash(m["tree"], 40)
    require(m["source"] == "/srv/academy/releases/" + m["candidate"], "candidate_source_namespace")
    for key in ("self_sha256", "plan_sha256", "common_sha256", "promoter_sha256", "baseline_helper_sha256"):
        hexhash(m[key])
    for key in ("execution_manifest", "promotion_manifest", "promotion_approval"):
        if key == "promotion_approval" and m[key] is None:
            continue
        exact(m[key], ("path", "sha256"))
        hexhash(m[key]["sha256"])
    exact(m["prepared"], ("directory", "site_sha256", "format_sha256"))
    require(m["prepared"]["format_sha256"] == sha(FORMAT_BYTES), "exact_format_bytes")
    require(
        m["prepared"]["site_sha256"] is None or re.fullmatch("[0-9a-f]{64}", m["prepared"]["site_sha256"]), "site_pin"
    )
    require(
        type(m["assets"]) is list and {a["url"] for a in m["assets"]} == set(URLS) and len(m["assets"]) == len(URLS),
        "fixed_assets",
    )
    for asset in m["assets"]:
        exact(asset, ("url", "sha256", "source_path", "installed_path", "wheel_path", "wheel_member"))
        hexhash(asset["sha256"])
        if asset["url"] in URLS[:2]:
            require(
                asset["source_path"] == m["source"] + asset["url"]
                and asset["installed_path"] is None
                and asset["wheel_path"] is None
                and asset["wheel_member"] is None,
                "product_asset_source",
            )
        else:
            require(
                asset["source_path"] is None
                and type(asset["installed_path"]) is str
                and asset["installed_path"].startswith(m["venv"] + "/lib/python3.12/site-packages/")
                and type(asset["wheel_path"]) is str
                and type(asset["wheel_member"]) is str
                and ".." not in Path(asset["wheel_member"]).parts
                and asset["wheel_member"].endswith(asset["url"]),
                "kernel_asset_parity_paths",
            )


def inputs(m, manifest_hash, args):
    global COMMON, PROMOTER
    COMMON = module(m["common_path"], m["common_sha256"], "candidate_execute.py")
    runtime_baseline(m)
    COMMON.host_execution_lock()
    for sig in COMMON.INTERRUPTS:
        PREVIOUS_SIGNALS[sig] = signal.signal(sig, COMMON.interrupt_stage)
    if args.mode == "prepare":
        require(
            args.approval is None and args.evidence_index is None and args.privacy_receipt is None,
            "prepare_no_approval",
        )
        return None, None, None, None
    PROMOTER = module(m["promoter_path"], m["promoter_sha256"], "candidate_promote.py")
    PROMOTER.COMMON = COMMON
    cm, ch = load(m["execution_manifest"]["path"])
    pm, ph = load(m["promotion_manifest"]["path"])
    require(ch == m["execution_manifest"]["sha256"] and ph == m["promotion_manifest"]["sha256"], "frozen_manifests")
    COMMON.validate_manifest(cm, "web")
    PROMOTER.validate_manifest(pm, "web")
    observed = runtime_baseline(m)
    require(
        canonical(observed) == canonical(COMMON.baseline_runtime(cm, "web"))
        and canonical(observed) == canonical(pm["roles"]["web"]["runtime_baseline"])
        and m["baseline_helper_sha256"] == cm["helpers"]["candidate_baseline.py"]
        and m["baseline_helper_sha256"] == pm["producers"]["candidate_baseline.py"],
        "same_frozen_runtime_baseline",
    )
    require(
        cm["self_sha256"] == m["common_sha256"]
        and pm["self_sha256"] == m["promoter_sha256"]
        and pm["common_sha256"] == m["common_sha256"],
        "same_reviewed_modules",
    )
    for key in ("candidate", "tree", "source", "venv"):
        require(m[key] == cm[key] == pm[key], "frozen_candidate_identity")
    require(pm["execution_manifest"] == m["execution_manifest"], "promotion_execution_binding")
    COMMON.SOURCE, COMMON.VENV = m["source"], m["venv"]
    require(
        args.approval and args.evidence_index and m["promotion_approval"] is not None,
        "actual_approval_evidence_required",
    )
    pa, pah = load(m["promotion_approval"]["path"])
    require(pah == m["promotion_approval"]["sha256"], "actual_promotion_approval")
    # Promotion authorization is validated by its own reviewed implementation.
    PROMOTER.authorization(pa, pm, ph, "promote")
    a, ah = load(args.approval)
    exact(
        a,
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
        a["schema"] == "AcademyNginxApproval.v1"
        and a["approved_by"] == "Michael"
        and a["manifest_sha256"] == manifest_hash
        and a["attempt"] == pa["attempt"],
        "actual_nginx_approval",
    )
    require(
        type(a["approved_unix"]) is int
        and type(a["expires_unix"]) is int
        and a["approved_unix"] <= time.time() < a["expires_unix"] <= a["approved_unix"] + 3600,
        "approval_window",
    )
    require(sha(read(a["approval_record_path"])) == a["approval_record_sha256"], "actual_approval_record")
    require(
        type(a["authorized_modes"]) is list
        and len(set(a["authorized_modes"])) == len(a["authorized_modes"])
        and set(a["authorized_modes"]) <= {"apply", "verify-assets"}
        and args.mode in a["authorized_modes"]
        and type(a["benign_privacy_probe"]) is bool,
        "authorized_modes",
    )
    evidence = PROMOTER.Evidence(args.evidence_index, pm, cm, pa, pah, ph, ch)
    evidence.active_authority = {
        "kind": "promotion", "phase": "promote",
        "manifest": dict(m["promotion_manifest"]),
        "approval": dict(m["promotion_approval"]),
    }
    evidence.validate_active_authority = PROMOTER.authorization
    return cm, pm, (a, ah, pa), evidence


def hold(cm, pm, pa, evidence):
    COMMON.verify_stage(cm, "web", evidence)
    catalog = PROMOTER.catalog_after(evidence, cm)
    require(
        type(catalog) is dict
        and catalog.get("schema") == "AcademyActiveCatalogObservation.v3"
        and type(evidence.active_catalog_observations) is list
        and evidence.active_catalog_observations
        and evidence.active_catalog_observations[-1] == catalog,
        "actual_active_catalog_observation_retained",
    )
    COMMON.exclusion(evidence, cm, pa, "web")
    PROMOTER.held_gate("web", pm, cm, pa, evidence)
    COMMON.stopped("web", cm)
    PROMOTER.paused_timers()
    COMMON.preserved("web", cm)


def run(argv, timeout=30):
    code, out, err = COMMON.run_group(argv, COMMON.clean_env(), timeout, stdin=subprocess.DEVNULL)
    metadata = dict(program=Path(argv[0]).name, exit_code=code, stdout_sha256=sha(out), stderr_sha256=sha(err))
    COMMANDS.append(metadata)
    require(code == 0, "fixed_command_failed")
    return out, metadata


def nginx_identity():
    raw = read("/run/nginx.pid", private=False, limit=128)
    require(re.fullmatch(rb"[1-9][0-9]*\n?", raw), "nginx_master_pid")
    pid = int(raw)
    ticks = COMMON.proc_ticks(pid)
    require(
        Path("/proc", str(pid)).stat().st_uid == 0 and os.readlink("/proc/" + str(pid) + "/exe") == "/usr/sbin/nginx",
        "nginx_master_exe",
    )
    children = COMMON.proc_bytes(Path("/proc") / str(pid) / "task" / str(pid) / "children").split()
    result = {int(p): COMMON.proc_ticks(int(p)) for p in children}
    require(result and COMMON.proc_ticks(pid) == ticks, "stable_nginx_children")
    roles = {}
    titles = {
        b"nginx: worker process": "worker",
        b"nginx: worker process is shutting down": "draining-worker",
        b"nginx: cache manager process": "cache-manager",
        b"nginx: cache loader process": "cache-loader",
    }
    for child, child_ticks in result.items():
        title = COMMON.proc_bytes(Path("/proc") / str(child) / "cmdline").rstrip(b"\0").strip()
        require(title in titles and COMMON.proc_ticks(child) == child_ticks, "supported_stable_nginx_child_role")
        roles[child] = titles[title]
    require(any(role == "worker" for role in roles.values()), "nginx_accepting_worker_generation")
    return dict(pid=pid, start_ticks=ticks, children=result, child_roles=roles)


def asset_bytes(asset):
    if asset["source_path"] is not None:
        raw = COMMON.read_bytes(asset["source_path"], limit=16000000)
    else:
        raw = COMMON.read_bytes(asset["installed_path"], limit=16000000)
        # Never import installed candidate code. Wheel contents are data only.
        wheel_raw = read(asset["wheel_path"], limit=100000000)
        import io

        with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
            matches = [z for z in archive.infolist() if z.filename == asset["wheel_member"]]
            require(len(matches) == 1 and matches[0].file_size <= 16000000, "exact_bounded_wheel_member")
            require(archive.read(matches[0]) == raw, "installed_wheel_parity")
    require(sha(raw) == asset["sha256"], "frozen_asset_hash")
    return raw


def fetch(path, referrer=None):
    require(
        path in (*URLS, "/health")
        or re.fullmatch(r"/__academy_metadata_probe_[0-9a-f]{32}\?academy_query_probe_[0-9a-f]{32}", path),
        "fixed_public_url",
    )
    argv = [
        "/usr/bin/curl",
        "--disable",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--max-filesize",
        "16000000",
        "--resolve",
        "academy.dotmac.io:443:149.102.135.97",
        "--write-out",
        "\n%{http_code}",
    ]
    if referrer is not None:
        require(
            re.fullmatch(r"https://academy\.dotmac\.io/__academy_referrer_probe_[0-9a-f]{32}", referrer),
            "benign_referrer",
        )
        argv += ["--referer", referrer]
    live()
    output, _ = run([*argv, "https://academy.dotmac.io" + path], 40)
    require(
        len(output) <= 16000004 and len(output) >= 4 and output[-4:-3] == b"\n" and output[-3:].isdigit(),
        "bounded_https_response",
    )
    return output[:-4], int(output[-3:])


def privacy_probe():
    token = os.urandom(16).hex()
    path = "/__academy_metadata_probe_" + token
    query = "academy_query_probe_" + os.urandom(16).hex()
    referrer = "https://academy.dotmac.io/__academy_referrer_probe_" + os.urandom(16).hex()
    parent = directory(LOG.parent)
    try:
        fd = os.open(LOG.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and not before.st_mode & 0o022,
            "trusted_log",
        )
        os.lseek(fd, before.st_size, os.SEEK_SET)
        _, status = fetch(path + "?" + query, referrer)
        require(status == 404, "benign_probe_expected_404")
        deadline, window = time.monotonic() + 15, b""
        while time.monotonic() < deadline:
            window += os.read(fd, 1000001 - len(window))
            require(len(window) <= 1000000, "bounded_log_window")
            rows = [r for r in window.splitlines(keepends=True) if path.encode() in r and r.endswith(b"\n")]
            if rows:
                break
            time.sleep(0.2)
        current = LOG.lstat()
        after = os.fstat(fd)
        require(
            (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            and after.st_size >= before.st_size,
            "stable_log_inode",
        )
        require(
            len(rows) == 1
            and re.fullmatch(
                rb'[^ ]+ \[[^\]\r\n]+\] "GET ' + re.escape(path.encode()) + rb' HTTP/[0-9.]+" 404 [0-9]+ [0-9.]+\n',
                rows[0],
            )
            is not None
            and query.encode() not in rows[0]
            and referrer.encode() not in rows[0],
            "actual_path_only_probe",
        )
        return dict(
            schema="AcademyNginxPrivacyObservation.v1",
            ok=True,
            http_status=status,
            inode=[before.st_dev, before.st_ino],
            window_sha256=sha(window),
            matching_line_sha256=sha(rows[0]),
            query_absent=True,
            referrer_absent=True,
            observed_unix=time.time(),
            probe_path_sha256=sha(path.encode()),
        )
    finally:
        os.close(fd)


def main():
    global AUTH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prepare", "apply", "verify-assets"), required=True)
    for key in ("manifest", "receipt"):
        parser.add_argument("--" + key, required=True)
    for key in ("approval", "evidence-index", "privacy-receipt"):
        parser.add_argument("--" + key)
    args = parser.parse_args()
    require(
        sys.platform == "linux" and os.getuid() == os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site,
        "linux_root_isolated_no_site",
    )
    os.umask(0o077)
    m, mh = load(args.manifest)
    validate_manifest(m, args.mode)
    require(
        sha(read(Path(__file__).absolute())) == m["self_sha256"]
        and sha(read(Path(args.manifest).parent / "nginx-plan.json")) == m["plan_sha256"],
        "reviewed_self_plan",
    )
    receipt = Path(args.receipt)
    packet = Path(m["prepared"]["directory"])
    require(
        receipt.parent == Path(args.manifest).parent == packet and re.fullmatch(r"[a-z0-9-]+\.json", receipt.name),
        "receipt_namespace",
    )
    cm, pm, authorization, evidence = inputs(m, mh, args)
    if authorization:
        AUTH, ah, pa = authorization
    else:
        ah = pa = None
    observed_runtime = runtime_baseline(m)
    before_site_sha256 = observed_runtime["nginx"]["site_sha256"]
    prior_static_root = observed_runtime["nginx"]["static_root"]
    result = dict(
        runtime_baseline_sha256=sha(canonical(observed_runtime)),
        baseline_helper_sha256=m["baseline_helper_sha256"],
        schema="AcademyNginxReceipt.v3",
        mode=args.mode,
        status="started",
        candidate=m["candidate"],
        tree=m.get("tree"),
        source=m["source"],
        venv=m.get("venv"),
        manifest_sha256=mh,
        promotion_manifest_sha256=None if args.mode == "prepare" else m["promotion_manifest"]["sha256"],
        helper_sha256=m["self_sha256"],
        approval_sha256=ah,
        attempt=None if pa is None else pa["attempt"],
        started_unix=time.time(),
        deployment_ready=False,
        observations={},
    )
    fresh(receipt, canonical(result), authorized=AUTH is not None)
    try:
        if args.mode == "prepare":
            require(
                args.approval is None and args.evidence_index is None and args.privacy_receipt is None,
                "prepare_no_approval",
            )
            original = read(SITE, private=False, mode=0o644)
            require(
                sha(original) == before_site_sha256 and not os.path.lexists(FORMAT), "pinned_live_site_fresh_format"
            )
            modified = transform(original, m["source"], prior_static_root)
            fresh(packet / "nginx-original.private", original)
            fresh(packet / "nginx-candidate.private", modified)
            fresh(packet / "nginx-format.private", FORMAT_BYTES)
            result.update(
                status="prepared_bytes_only",
                before_sha256=sha(original),
                site_sha256=sha(modified),
                format_sha256=sha(FORMAT_BYTES),
                privacy_proven=False,
            )
        elif args.mode == "apply":
            require(args.privacy_receipt is None and m["prepared"]["site_sha256"] is not None, "apply_frozen_site")
            hold(cm, pm, pa, evidence)
            original = read(SITE, private=False, mode=0o644)
            candidate = read(packet / "nginx-candidate.private")
            format_bytes = read(packet / "nginx-format.private")
            require(
                sha(original) == before_site_sha256
                and read(packet / "nginx-original.private") == original
                and transform(original, m["source"], prior_static_root) == candidate
                and sha(candidate) == m["prepared"]["site_sha256"]
                and format_bytes == FORMAT_BYTES
                and not os.path.lexists(FORMAT),
                "all_prepared_and_live_bytes",
            )
            for asset in m["assets"]:
                asset_bytes(asset)
            _, result["observations"]["nginx_before"] = run(["/usr/sbin/nginx", "-t"])
            before_master = nginx_identity()
            hold(cm, pm, pa, evidence)
            fresh(packet / "nginx-apply-intent.json", canonical(result), authorized=True)
            fresh(FORMAT, format_bytes, mode=0o644, authorized=True, private=False)
            temporary = SITE.parent / (".academy-candidate-" + m["candidate"] + ".tmp")
            fresh(temporary, candidate, mode=0o644, authorized=True, private=False)
            parent = directory(SITE.parent)
            try:
                require(
                    sha(read(SITE, private=False, mode=0o644)) == before_site_sha256
                    and read(temporary, private=False, mode=0o644) == candidate,
                    "site_compare_and_swap",
                )
                live()
                os.replace(temporary.name, SITE.name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
            _, result["observations"]["nginx_after"] = run(["/usr/sbin/nginx", "-t"])
            hold(cm, pm, pa, evidence)
            live()
            _, result["observations"]["reload"] = run(["/usr/sbin/nginx", "-s", "reload"])
            deadline = time.monotonic() + 30
            while True:
                after_master = nginx_identity()
                require(
                    (after_master["pid"], after_master["start_ticks"])
                    == (before_master["pid"], before_master["start_ticks"]),
                    "same_nginx_master",
                )
                retained = set(before_master["children"]) & set(after_master["children"])
                new_workers = set(after_master["children"]) - set(before_master["children"])
                draining, retained_auxiliary = [], []
                for pid in retained:
                    require(after_master["children"][pid] == before_master["children"][pid], "prior_child_pid_reuse")
                    previous_role = before_master["child_roles"][pid]
                    current_role = after_master["child_roles"][pid]
                    if previous_role in {"worker", "draining-worker"} and current_role == "draining-worker":
                        draining.append(pid)
                    elif previous_role in {"cache-manager", "cache-loader"} and current_role == previous_role:
                        retained_auxiliary.append(pid)
                ready = [pid for pid in new_workers if after_master["child_roles"][pid] == "worker"]
                if ready and set(draining + retained_auxiliary) == retained:
                    break
                require(time.monotonic() < deadline, "nginx_new_generation_unconfirmed")
                time.sleep(0.2)
            _, result["observations"]["nginx_expanded_configuration"] = run(["/usr/sbin/nginx", "-T"])
            require(
                read(SITE, private=False, mode=0o644) == candidate
                and read(FORMAT, private=False, mode=0o644) == format_bytes,
                "actual_config_readback",
            )
            hold(cm, pm, pa, evidence)
            result.update(
                status="config_applied_new_generation_observed",
                site_sha256=sha(candidate),
                format_sha256=sha(format_bytes),
                privacy_proven=False,
                nginx_master=after_master,
                new_worker_pids=sorted(ready),
                prior_draining_worker_pids=sorted(draining),
                retained_auxiliary_pids=sorted(retained_auxiliary),
                loaded_identity_limit="Same-master reload plus observed worker titles and exact disk readback; "
                "public fresh-connection asset parity and actual privacy probe remain required.",
            )
        else:
            require(m["prepared"]["site_sha256"] is not None, "verify_frozen_site")
            # New web must have genuine promotion and current same-process proof.
            report = PROMOTER.fresh_other_process("web", pm, cm, pa, evidence)
            ownership = PROMOTER.candidate_ownership("web", pm, cm)
            require(
                ownership["pid"] > 1
                and ownership["pid"] == report["pid"]
                and ownership["start_ticks"] == report["start_ticks"],
                "actual_new_web_process",
            )
            PROMOTER.paused_timers()
            PROMOTER.held_gate("web", pm, cm, pa, evidence)
            COMMON.preserved("web", cm)
            require(
                sha(read(SITE, private=False, mode=0o644)) == m["prepared"]["site_sha256"]
                and read(FORMAT, private=False, mode=0o644) == FORMAT_BYTES,
                "current_config_identity",
            )
            _, health_status = fetch("/health")
            require(health_status == 200, "public_candidate_health")
            results = []
            for asset in m["assets"]:
                expected = asset_bytes(asset)
                body, status = fetch(asset["url"])
                require(status == 200 and body == expected, "public_https_asset_parity")
                results.append(dict(url=asset["url"], status=status, sha256=sha(body), size=len(body)))
            result.update(
                status="public_assets_verified",
                assets=results,
                site_sha256=m["prepared"]["site_sha256"],
                format_sha256=sha(FORMAT_BYTES),
                privacy_proven=False,
            )
            if args.privacy_receipt:
                require(
                    AUTH["benign_privacy_probe"] is True
                    and Path(args.privacy_receipt).parent == packet
                    and re.fullmatch(r"[a-z0-9-]+\.json", Path(args.privacy_receipt).name),
                    "privacy_probe_authorized",
                )
                proof = privacy_probe()
                proof.update(
                    candidate=m["candidate"],
                    tree=m["tree"],
                    attempt=pa["attempt"],
                    manifest_sha256=mh,
                    approval_sha256=ah,
                    helper_sha256=m["self_sha256"],
                    site_sha256=m["prepared"]["site_sha256"],
                    format_sha256=sha(FORMAT_BYTES),
                )
                fresh(args.privacy_receipt, canonical(proof), authorized=True)
                result.update(privacy_proven=True, privacy_receipt_sha256=sha(canonical(proof)))
        result["evidence"] = {} if evidence is None else evidence.used
    except BaseException as error:
        result.update(
            status="manual_fix_forward_hold",
            failure_type=type(error).__name__,
            recovery=(
                "Keep web stopped if not yet promoted, gate held and timers paused; "
                "retain all partial artifacts. No automatic restore."
            ),
        )
        raise
    finally:
        # Common run_group has already bounded and drained each owned child group.
        # Ignore further catchable interrupts only while retaining the final evidence.
        for sig in COMMON.INTERRUPTS:
            signal.signal(sig, signal.SIG_IGN)
        result["commands"] = COMMANDS
        result["process_groups"] = COMMON.PROCESS_GROUPS
        result["active_catalog_observations"] = [] if evidence is None else evidence.active_catalog_observations
        if any(group.get("confirmed") is not True for group in COMMON.PROCESS_GROUPS):
            result.update(status="manual_fix_forward_hold", failure_type="owned_process_cleanup_unconfirmed")
        result["completed_unix"] = time.time()
        try:
            # Evidence persistence remains permitted after expiry; never changes a service/config.
            fresh(receipt.with_name(receipt.stem + "-result.json"), canonical(result))
        finally:
            for sig, handler in PREVIOUS_SIGNALS.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print("Nginx operation refused or failed; inspect root-private result. Manual hold.", file=sys.stderr)
        sys.exit(2)
