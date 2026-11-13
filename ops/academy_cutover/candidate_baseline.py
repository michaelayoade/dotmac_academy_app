"""Pure closed Academy runtime descriptor contract; observations grant no authority.

Call validate_runtime with the independently established role and dotmac uid first.
Accessors accept that validated descriptor and return detached data. This module
performs no IO, discovers no state and never interprets environment or commands.
Load only exact hash-reviewed bytes through the consumer's safe-FD loader.
"""

import copy
import re

SCHEMA = "AcademyRuntimeBaseline.v1"
D122 = "d12260b6996b18b27e04a784042f764bd583952d"
RELEASE_7EF = "7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46"
SHARED = "/home/dotmac/projects/dotmac_academy_v2"
HOSTS = {"web": "vmi2490731", "lab": "academy-labs"}
RUNTIMES = {
    D122: (
        "/home/dotmac/projects/academy-v2-csp-stage-" + D122,
        "/home/dotmac/.local/share/academy-v2-venvs/" + D122,
    ),
    RELEASE_7EF: (
        "/home/dotmac/projects/academy-v2-release-" + RELEASE_7EF,
        "/home/dotmac/.local/share/academy-v2-venvs/" + RELEASE_7EF,
    ),
}
WEB_UNITS = (
    "academy-v2-web",
    "academy-v2-admin-report",
    "academy-v2-email-digest",
    "academy-v2-email-outbox",
    "academy-v2-erp-training-sync",
    "academy-v2-hr-report",
    "academy-v2-learner-digest",
    "academy-v2-reminders",
)
LAB_UNITS = ("academy-v2-lab-worker",)


def _require(ok, reason):
    if not ok:
        raise ValueError(reason)


def _exact(value, names):
    _require(type(value) is dict and set(value) == set(names), "runtime_strict_fields")


def _hash(value, size=64):
    _require(
        type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None,
        "runtime_hash_format",
    )


def validate_runtime(value, role, dotmac_uid):
    """Validate the closed descriptor and return an independent deep copy.

    Hashes bind externally observed bytes, not acceptance. The consumer must
    independently establish Git head/tree equality, ownership, link shape and
    fresh filesystem/service state; this pure function cannot establish them.
    """
    _require(type(role) is str and role in HOSTS, "runtime_role")
    _require(type(dotmac_uid) is int and dotmac_uid > 0, "runtime_dotmac_uid")
    _exact(value, ("schema", "role", "hostname", "units", "environment", "uploads", "nginx"))
    _require(value["schema"] == SCHEMA, "runtime_schema")
    _require(value["role"] == role and value["hostname"] == HOSTS[role], "runtime_host_role")
    units = WEB_UNITS if role == "web" else LAB_UNITS
    _exact(value["units"], units)
    for unit in units:
        runtime = value["units"][unit]
        _exact(runtime, ("head", "tree", "source", "venv"))
        _hash(runtime["head"], 40)
        _hash(runtime["tree"], 40)
        _require(runtime["head"] in RUNTIMES, "runtime_prior_head")
        _require(role != "lab" or runtime["head"] == D122, "runtime_lab_prior_head")
        _require(
            (runtime["source"], runtime["venv"]) == RUNTIMES[runtime["head"]],
            "runtime_head_path_tuple",
        )
    environment = value["environment"]
    _exact(environment, ("path", "target", "sha256", "uid", "gid", "mode", "link_target"))
    env_paths = (SHARED + "/.env", *(paths[0] + "/.env" for paths in RUNTIMES.values()))
    _require(
        type(environment["path"]) is str
        and type(environment["target"]) is str
        and environment["path"] in env_paths
        and environment["target"] in env_paths,
        "runtime_environment_path",
    )
    _hash(environment["sha256"])
    _require(
        type(environment["uid"]) is int and environment["uid"] in (0, dotmac_uid),
        "runtime_environment_owner",
    )
    _require(type(environment["gid"]) is int and environment["gid"] >= 0, "runtime_environment_group")
    _require(type(environment["mode"]) is int and environment["mode"] == 0o600, "runtime_environment_mode")
    _require(
        (environment["path"] == environment["target"] and environment["link_target"] is None)
        or (
            environment["path"] != environment["target"]
            and type(environment["link_target"]) is str
            and environment["link_target"] == environment["target"]
        ),
        "runtime_environment_single_link",
    )
    uploads = value["uploads"]
    _require(type(uploads) is dict and set(uploads) <= {"avatars", "figures"}, "runtime_upload_fields")
    for name, upload in uploads.items():
        _exact(upload, ("target", "inventory_sha256"))
        allowed = tuple(root + "/static/" + name for root in (SHARED, *(p[0] for p in RUNTIMES.values())))
        _require(type(upload["target"]) is str and upload["target"] in allowed, "runtime_upload_target")
        _hash(upload["inventory_sha256"])
    if role == "lab":
        _require(value["nginx"] is None, "runtime_lab_nginx_null")
    else:
        _exact(value["nginx"], ("static_root", "site_sha256"))
        _require(
            type(value["nginx"]["static_root"]) is str
            and value["nginx"]["static_root"] in tuple(paths[0] for paths in RUNTIMES.values()),
            "runtime_nginx_static_root",
        )
        _hash(value["nginx"]["site_sha256"])
    return copy.deepcopy(value)


def unit_runtime(value, unit):
    """Return a detached unit tuple from an already validated descriptor."""
    _require(type(unit) is str and unit in value["units"], "runtime_unit")
    return copy.deepcopy(value["units"][unit])


def primary_runtime(value):
    return unit_runtime(value, "academy-v2-web" if value["role"] == "web" else "academy-v2-lab-worker")


def environment_file(value):
    return copy.deepcopy(value["environment"])


def upload_targets(value):
    return copy.deepcopy(value["uploads"])


def nginx_static_root(value):
    return None if value["nginx"] is None else value["nginx"]["static_root"]


def forbidden_runtime_paths():
    """Return every prior source and venv, irrespective of the active host role."""
    return tuple(path for paths in RUNTIMES.values() for path in paths)
