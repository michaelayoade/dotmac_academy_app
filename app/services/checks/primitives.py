"""Check primitives: command, probe, config_grep.

Each primitive takes ``(check, engine, handle, seed)`` and returns
``{"pass": bool, "actual": ..., "expected": ...}``.
"""

from __future__ import annotations

import json
import re

from jsonpath_ng import parse as jp_parse

from app.services.lab_seed import interpolate


def eval_command(check, engine, handle, seed):
    """Run a command on a node and assert on stdout/exit code.

    ``transport: ssh`` routes to ``engine.ssh_exec`` (RouterOS CHR via mgmt IP);
    otherwise the command runs through ``engine.exec`` as ``sh -c``.
    """
    cmd = interpolate(check["command"], seed)
    if check.get("transport") == "ssh":  # RouterOS CHR node: SSH to mgmt IP
        res = engine.ssh_exec(
            handle,
            check["node"],
            cmd,
            user=check.get("user", "admin"),
            password=interpolate(check.get("password", ""), seed),
        )
    else:  # container node: docker exec
        res = engine.exec(handle, check["node"], ["sh", "-c", cmd])
    a = check.get("assert", {})
    expected = a.get("equals")
    if "jsonpath" in a:
        try:
            actual = str(
                next(m.value for m in jp_parse(a["jsonpath"]).find(json.loads(res.stdout)))
            )
        except Exception:
            actual = None
        ok = actual == str(expected)
    elif "regex" in a:
        actual = res.stdout.strip()
        ok = re.search(a["regex"], res.stdout) is not None
        expected = a["regex"]
    else:
        actual = res.exit_code
        ok = res.exit_code == a.get("exit_code", 0)
        expected = a.get("exit_code", 0)
    return {"pass": ok, "actual": actual, "expected": expected}


def eval_probe(check, engine, handle, seed):
    """Reachability probe: ping / dns / http."""
    p = check["probe"]
    target = interpolate(p.get("target", ""), seed)
    if p["kind"] == "ping":
        res = engine.exec(handle, check["node"], ["ping", "-c", str(p["count"]), target])
        m = re.search(r"(\d+) received", res.stdout)
        got = int(m.group(1)) if m else 0
        ok = got >= p.get("min_success", 1)
        return {
            "pass": ok,
            "actual": f"{got} received",
            "expected": f">={p.get('min_success', 1)}",
        }
    if p["kind"] == "dns":
        res = engine.exec(handle, check["node"], ["nslookup", target])
        ok = "Address" in res.stdout
        return {"pass": ok, "actual": res.stdout.strip()[:120], "expected": f"resolves {target}"}
    if p["kind"] == "http":
        res = engine.exec(
            handle,
            check["node"],
            ["sh", "-c", f"curl -s -o /dev/null -w '%{{http_code}}' {target}"],
        )
        ok = res.stdout.strip() == str(p.get("status", 200))
        return {"pass": ok, "actual": res.stdout.strip(), "expected": str(p.get("status", 200))}
    raise ValueError(f"unknown probe {p['kind']}")


def eval_config_grep(check, engine, handle, seed):
    """Assert that ``cat <file>`` on the node contains an interpolated substring."""
    res = engine.exec(handle, check["node"], ["sh", "-c", f"cat {check['file']}"])
    pat = interpolate(check["contains"], seed)
    ok = pat in res.stdout
    return {"pass": ok, "actual": ("present" if ok else "absent"), "expected": pat}
