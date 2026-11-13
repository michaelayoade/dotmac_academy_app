"""Fixed source-only SSH forced-command entry for the three current census leaves.

Install reviewed bytes only at ENTRYPOINT, root-owned 0644, with a root-owned
0644 POLICY. No keys, accounts, sudo rules or policy instances are provisioned by
this module. The producer hash in policy is a declaration: the producer's protected
bootstrap must verify actual source and authority. In particular the lab receiver
cannot inspect the producer under /root. No stdin bytes are consumed here.
execve preserves the request pipes; it does not establish remote timeout cleanup.
"""

import hashlib
import json
import os
import pwd
import re
import socket
import stat
import sys

ENTRYPOINT = "/usr/local/libexec/academy-census-peer-entry.py"
POLICY = "/etc/academy-census-peer-entry.json"
LIMIT = 8192
HOSTS = {"web": "vmi2490731", "lab": "academy-labs"}
OPERATIONS = {"gate-web": "web", "stopped-web": "web", "stopped-lab": "lab"}
FIELDS = ("schema", "role", "hostname", "receiving_uid", "producer", "peer_packet_root", "entrypoint_sha256")
ROOT_PATH = re.compile(r"/root/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def _require(condition):
    if not condition:
        raise ValueError("peer_entry_refused")


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def _root_path(value):
    _require(type(value) is str and len(value) <= 2048 and ROOT_PATH.fullmatch(value) is not None)
    _require(all(part not in (".", "..") for part in value.split("/")))
    return value


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def _file_identity(info):
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(info):
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def _protected(path):
    """Read only either fixed file, anchored through every root-owned parent."""
    _require(path in (ENTRYPOINT, POLICY))
    descriptors = []
    anchors = []
    file_fd = None
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        parent = os.open("/", flags | os.O_DIRECTORY)
        descriptors.append(parent)
        root_identity = _identity(os.fstat(parent))
        _directory(os.fstat(parent))
        parts = path.split("/")[1:]
        for name in parts[:-1]:
            child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
            descriptors.append(child)
            meta = os.fstat(child)
            _directory(meta)
            anchors.append((parent, name, child, _identity(meta)))
            parent = child
        file_fd = os.open(parts[-1], flags, dir_fd=parent)
        before = os.fstat(file_fd)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o644
                 and before.st_uid == 0 and before.st_nlink == 1 and 0 < before.st_size <= LIMIT)
        raw = bytearray()
        while len(raw) <= LIMIT:
            chunk = os.read(file_fd, LIMIT + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        _require(len(raw) == before.st_size and len(raw) <= LIMIT
                 and _file_identity(before) == _file_identity(os.fstat(file_fd))
                 and _file_identity(before) == _file_identity(os.stat(parts[-1], dir_fd=parent,
                                                                     follow_symlinks=False)))
        for parent_fd, name, child_fd, identity in anchors:
            _require(identity == _identity(os.fstat(child_fd))
                     == _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)))
            _directory(os.fstat(child_fd))
        _require(root_identity == _identity(os.fstat(descriptors[0]))
                 == _identity(os.stat("/", follow_symlinks=False)))
        _directory(os.fstat(descriptors[0]))
        return bytes(raw)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value)
        value[key] = item
    return value


def validate_policy(value):
    """Closed static policy; dictionary validation never establishes file custody."""
    _exact(value, FIELDS)
    _require(value["schema"] == "AcademyCensusPeerEntryPolicy.v1")
    role = value["role"]
    _require(type(role) is str and role in HOSTS and value["hostname"] == HOSTS[role])
    uid = value["receiving_uid"]
    _require(type(uid) is int and 0 <= uid < 2**32 and (uid == 0 if role == "web" else uid > 0))
    _exact(value["producer"], ("path", "sha256"))
    path = _root_path(value["producer"]["path"])
    _require(path.rsplit("/", 1)[-1] == "candidate_external_census.py")
    _root_path(value["peer_packet_root"])
    for digest in (value["producer"]["sha256"], value["entrypoint_sha256"]):
        _require(type(digest) is str and HASH.fullmatch(digest) is not None)
    return value


def commands(policy):
    """Own finite argv only; the untrusted original command is never parsed."""
    validate_policy(policy)
    result = {}
    for operation, role in OPERATIONS.items():
        if role == policy["role"]:
            inputs = policy["peer_packet_root"] + "/current-" + operation + "-inputs.json"
            _root_path(inputs)
            argv = (["/usr/bin/sudo", "-n", "--"] if role == "lab" else []) + [
                "/usr/bin/python3.12", "-B", "-I", "-S", policy["producer"]["path"],
                "--inputs", inputs, "--current-request-stdin",
            ]
            result[" ".join(argv)] = argv
    return result


def dispatch():
    """Validate actual receiving runtime and custody, then replace this process."""
    _require(sys.platform == "linux" and sys.version_info[:2] == (3, 12)
             and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
             and sys.argv == [ENTRYPOINT] and __file__ == ENTRYPOINT)
    own = _protected(ENTRYPOINT)
    policy = validate_policy(json.loads(_protected(POLICY), object_pairs_hook=_pairs))
    _require(hashlib.sha256(own).hexdigest() == policy["entrypoint_sha256"])
    role = policy["role"]
    expected_uid = 0 if role == "web" else pwd.getpwnam("dotmac").pw_uid
    _require(type(expected_uid) is int and expected_uid == policy["receiving_uid"]
             and os.getuid() == os.geteuid() == expected_uid and socket.gethostname() == HOSTS[role])
    original = os.environ.get("SSH_ORIGINAL_COMMAND")
    _require(type(original) is str and 0 < len(original.encode("utf-8")) <= 4096)
    allowed = commands(policy)
    _require(original in allowed)
    argv = allowed[original]
    os.execve(argv[0], argv, dict(CLEAN_ENV))  # noqa: S606 -- finite module-owned argv, no shell
    raise ValueError("peer_entry_refused")  # execve must replace the process.


def main():
    try:
        dispatch()
    except (Exception, KeyboardInterrupt):
        try:
            os.write(2, b"census peer entry refused\n")
        except OSError:
            pass
    return 111


if __name__ == "__main__":
    raise SystemExit(main())
