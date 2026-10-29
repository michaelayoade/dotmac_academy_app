"""Academy HOSTEDTEST disposable resource owner; source candidate, NOT qualified.

The caller supplies predeclared data, never a DSN, verifier, or service handle.
Only the product coordinator may own its root transaction. This owner provides
no commit, rollback, release, runtime credential, or admission operation.

Image initialization reference (pin exact image/entrypoint in root CI review):
https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh
Local SCRAM MUST be explicit: the image's ordinary initdb local default is trust.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import secrets
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import weakref
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import cast

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine, RootTransaction
from sqlalchemy.pool import NullPool

_FIELDS = (
    "target_database",
    "setup_session",
    "service_image",
    "server_version_num",
    "encoding",
    "locale_provider",
    "lc_collate",
    "lc_ctype",
    "icu_locale",
    "collation_version",
    "actual_collation_version",
    "extension_versions",
)
_PREFIX = "academy_retained_environment_"
_PURPOSES = ("environment", "history", "assembly")
_HBA = "local all postgres scram-sha-256\nlocal all all reject\nhost all all all reject\n"
_RUNTIME = ("app_user", "platform_api", "academy_lab_worker", "outbox_dispatcher", "platform_outbox_dispatcher")
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
_INSPECT_FIELDS = (
    "container_id",
    "image_id",
    "created",
    "running",
    "started_at",
    "restart_count",
    "network_mode",
    "port_bindings",
    "ports",
    "mounts",
    "command",
    "user",
    "privileged",
    "readonly_rootfs",
    "networks",
)


class HostedGenesisRefused(RuntimeError):
    """Owner continuity lost. Resource remains poisoned, including after repair."""


def _need(condition: bool) -> None:
    if not condition:
        raise HostedGenesisRefused("Academy hosted disposable resource refused")


def _require_container_identity(actual: tuple[object, ...], expected: tuple[object, ...]) -> None:
    """Report only allowlisted field names; never expose inspect values."""
    _need(len(actual) == len(expected) == len(_INSPECT_FIELDS))
    changed = [name for name, before, after in zip(_INSPECT_FIELDS, expected, actual, strict=True) if before != after]
    if changed:
        raise HostedGenesisRefused("Academy hosted container continuity changed: " + ",".join(changed))


def _canonical_mounts(mounts: object) -> list[object]:
    """Conserve every mount field while ignoring Docker's array enumeration order."""
    _need(type(mounts) is list)
    records = cast(list[object], mounts)
    _need(all(type(record) is dict for record in records))
    return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))


def _data(settings: object) -> tuple[tuple[str, object], ...]:
    _need(type(settings) is dict and set(settings) == {_PREFIX + k for k in _FIELDS})
    settings = cast(dict[str, object], settings)
    pairs = tuple((k, settings[_PREFIX + k]) for k in _FIELDS)
    values = dict(pairs)
    _need(type(values["target_database"]) is str and bool(_ID.fullmatch(values["target_database"])))
    _need(values["setup_session"] == "postgres")
    _need(type(values["server_version_num"]) is int and 160000 <= values["server_version_num"] < 170000)
    _need(values["encoding"] == "UTF8" and values["locale_provider"] == "c")
    _need(values["lc_collate"] == "en_US.utf8" and values["lc_ctype"] == "en_US.utf8")
    _need(values["icu_locale"] is None)
    _need(type(values["collation_version"]) is str)
    _need(values["collation_version"] == values["actual_collation_version"])
    _need(values["extension_versions"] == (("plpgsql", "1.0"),))
    for name, value in pairs:
        if name == "extension_versions":
            _need(type(value) is tuple and all(type(x) is tuple for x in value))
        else:
            _need(value is None or type(value) in (str, int))
            if type(value) is str:
                _need(0 < len(value) <= 240 and value.isascii() and value.isprintable())
    return pairs


@dataclass(frozen=True, slots=True, repr=False)
class HostedGenesisDeclaration:
    """Reconstructed immutable expectations; freely constructible, no authority."""

    image: str
    platform: str
    purposes: tuple[tuple[str, tuple[tuple[str, object], ...]], ...]


def declaration_from_settings(settings: Mapping[str, object]) -> HostedGenesisDeclaration:
    _need(type(settings) is dict and set(settings) == {"image", "platform", *_PURPOSES})
    image, platform = settings["image"], settings["platform"]
    _need(type(image) is str and bool(re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image)))
    _need(type(platform) is str and platform in ("linux/amd64", "linux/arm64"))
    purposes = tuple((p, _data(settings[p])) for p in _PURPOSES)
    _need(len({dict(v)["target_database"] for _, v in purposes}) == 3)
    _need(all(dict(v)["service_image"] == image for _, v in purposes))
    return HostedGenesisDeclaration(cast(str, image), cast(str, platform), purposes)


class _Handle:
    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise TypeError("Only the hosted resource owner issues contexts")

    def __reduce__(self):
        raise TypeError("Hosted contexts are not serializable")


_ISSUED: weakref.WeakKeyDictionary[_Handle, _Owner] = weakref.WeakKeyDictionary()


def _private_directory(path: Path) -> tuple[int, int]:
    _need(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return info.st_dev, info.st_ino


def _private_file(path: Path, expected: bytes) -> tuple[int, int]:
    info = path.lstat()
    _need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
    )
    _need(path.read_bytes() == expected)
    return info.st_dev, info.st_ino


_WATCH_MASK = 0x4000EFFF
_WATCH_HEADER = struct.Struct("=iIII")
_WATCH_NAMES = (
    b"",
    b"control",
    b"socket",
    b"data",
    b"hba",
    b"password",
    b"postgresql.conf",
    b"postgresql.auto.conf",
    b"pg_hba.conf",
    b"pg_ident.conf",
    b".s.PGSQL.5432",
    b".s.PGSQL.5432.lock",
)


def _first_watch_event(data, descriptors):
    _need(type(data) is bytes and 16 <= len(data) <= 4096)
    _need(type(descriptors) is dict and len(descriptors) <= 10)
    _need(all(type(key) is int and type(value) is int and 0 <= value <= 10 for key, value in descriptors.items()))
    descriptor, mask, _, length = _WATCH_HEADER.unpack_from(data)
    _need(16 + length <= len(data))
    name = data[16 : 16 + length]
    if length:
        end = name.find(b"\0")
        _need(end >= 0 and not any(name[end:]))
        name = name[:end]
    name_class = _WATCH_NAMES.index(name) + 1 if name in _WATCH_NAMES else 0
    return (descriptors.get(descriptor, 0), name_class, mask & _WATCH_MASK, bool(mask & ~_WATCH_MASK))


class _Owner:
    def __init__(self, declaration: HostedGenesisDeclaration, purpose: str) -> None:
        # Reconstruct even exact-type dataclasses: frozen is not validation.
        _need(type(declaration) is HostedGenesisDeclaration and purpose in _PURPOSES)
        rebuilt = declaration_from_settings(
            {
                "image": declaration.image,
                "platform": declaration.platform,
                **{p: {_PREFIX + k: v for k, v in pairs} for p, pairs in declaration.purposes},
            }
        )
        _need(declaration == rebuilt)
        _need(sys.platform == "linux" and os.getuid() != 0)
        _need(os.environ.get("CI") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
        # Preflight strings are diagnostics only. Root verifies actual GitHub
        # authority separately. No supplied Docker host/context/config accepted.
        _need(
            not any(
                os.environ.get(k)
                for k in (
                    "DOCKER_HOST",
                    "DOCKER_CONTEXT",
                    "DOCKER_CONFIG",
                    "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH",
                )
            )
        )
        docker = shutil.which("docker")
        _need(docker is not None and Path(docker).is_absolute())
        self.docker = str(Path(cast(str, docker)).resolve(strict=True))
        self.declaration = rebuilt
        self.expected = MappingProxyType(dict(dict(rebuilt.purposes)[purpose]))
        self.poisoned = False
        self.pid = os.getpid()
        # Resources remain optional for partial-setup cleanup. Phase-method
        # casts reflect setup, then replay/coordinator acquisition, then bind_root;
        # the existing identity/continuity checks still enforce that sequence.
        self.container: str | None = None
        self.name = "academy-genesis-" + secrets.token_hex(16)
        self.home: Path | None = None
        self.engine: Engine | None = None
        self.control_engine: Engine | None = None
        self.control: Connection | None = None
        self.connection: Connection | None = None
        self.root: RootTransaction | None = None
        self.xid: str | None = None
        self.watch: int | None = None
        self._watch_descriptors: dict[int, int] = {}
        self._watch_event: tuple[int, int, int, bool] | None = None
        self.backends: dict[int, datetime] = {}
        self.logs = b""
        self.events: tuple[()] | tuple[tuple[bytes, ...], tuple[bytes, ...]] = ()
        self.sealed = False
        self.replayed = False
        self.root_listeners: list[tuple[Connection, str, Callable[..., None]]] = []

    def command(self, *argv: str, limit: int = 65536) -> bytes:
        result = subprocess.run(  # noqa: S603 - fixed Docker argv; no shell, environment dump or stderr
            (self.docker, *argv),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=45,
        )
        _need(len(result.stdout) <= limit)
        return result.stdout

    def inspect(self):
        # Explicit allowlist. Never inspect Config.Env, labels or raw inspect.
        template = (
            "{{json .Id}} {{json .Image}} {{json .Created}} {{json .State.Running}} "
            "{{json .State.StartedAt}} {{json .RestartCount}} {{json .HostConfig.NetworkMode}} "
            "{{json .HostConfig.PortBindings}} {{json .NetworkSettings.Ports}} "
            "{{json .Mounts}} {{json .Config.Cmd}} {{json .Config.User}} "
            "{{json .HostConfig.Privileged}} {{json .HostConfig.ReadonlyRootfs}} "
            "{{json .NetworkSettings.Networks}}"
        )
        raw = self.command("inspect", "--format", template, cast(str, self.container)).decode("ascii")
        decoder = json.JSONDecoder()
        facts = []
        while raw.strip():
            value, end = decoder.raw_decode(raw.lstrip())
            facts.append(value)
            raw = raw.lstrip()[end:]
        # Mount records identify bindings; their array order is not identity.
        # Keep every field, duplicate and unknown attribute in the comparison.
        _need(len(facts) == len(_INSPECT_FIELDS))
        facts[9] = _canonical_mounts(facts[9])
        return tuple(facts)

    def setup(self):
        _need(self.command("context", "show").strip() == b"default")
        self.home = Path(tempfile.mkdtemp(prefix="academy-genesis-", dir="/tmp")).resolve(strict=True)
        self.home_identity = _private_directory(self.home)
        self.dirs = {}
        for name in ("socket", "data", "control"):
            path = self.home / name
            path.mkdir(mode=0o700)
            self.dirs[name] = _private_directory(path)
        self.home_identity = _private_directory(self.home)
        self.secret = secrets.token_urlsafe(48).encode("ascii")
        self.hba = self.home / "control/hba"
        self.password = self.home / "control/password"
        for path, data in ((self.hba, _HBA.encode()), (self.password, self.secret)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        self.file_ids = (_private_file(self.hba, _HBA.encode()), _private_file(self.password, self.secret))
        # Local SCRAM includes the image's temporary bootstrap server. The
        # official entrypoint supplies PGPASSWORD for its own setup psql.
        self.args = (
            "postgres",
            "-c",
            "listen_addresses=",
            "-c",
            "unix_socket_directories=/var/run/postgresql",
            "-c",
            "unix_socket_permissions=0700",
            "-c",
            "hba_file=/academy-control/hba",
            "-c",
            "password_encryption=scram-sha-256",
            "-c",
            "log_connections=on",
            "-c",
            "log_disconnections=on",
            "-c",
            "log_line_prefix=%p ",
            "-c",
            "log_statement=none",
            "-c",
            "log_min_error_statement=panic",
            "-c",
            "log_error_verbosity=terse",
            "-c",
            "max_prepared_transactions=0",
            "-c",
            "wal_level=minimal",
            "-c",
            "max_wal_senders=0",
        )
        # Named first, then create: cancellation after actual create still has
        # a unique owned name to resolve for cleanup. Never attach/adopt.
        self.container = (
            self.command(
                "create",
                "--name",
                self.name,
                "--pull=never",
                "--platform",
                self.declaration.platform,
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=32m",  # noqa: S108 - private container tmpfs, not host shared storage
                "--mount",
                f"type=bind,src={self.home / 'socket'},dst=/var/run/postgresql",
                "--mount",
                f"type=bind,src={self.home / 'data'},dst=/var/lib/postgresql/data",
                "--mount",
                f"type=bind,src={self.home / 'control'},dst=/academy-control,readonly",
                "--env",
                "POSTGRES_PASSWORD_FILE=/academy-control/password",
                "--env",
                "POSTGRES_DB=postgres",
                "--env",
                "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=reject "
                "--locale=en_US.utf8 --encoding=UTF8",
                self.declaration.image,
                *self.args,
            )
            .decode("ascii")
            .strip()
        )
        _need(bool(re.fullmatch(r"[a-f0-9]{64}", self.container)))
        self.command("start", self.container)
        # Readiness requires FINAL postmaster; temporary bootstrap must exit.
        for _ in range(300):
            # PostgreSQL writes stderr, so Docker logs must merge inside the
            # child (see _server_logs), never expose it in a tool/artifact.
            logs = self._server_logs()
            if (
                b"PostgreSQL init process complete" in logs
                and logs.count(b"database system is ready to accept connections") >= 2
            ):
                break
            _need(self.inspect()[3] is True)
            time.sleep(0.1)
        else:
            raise HostedGenesisRefused("Hosted PostgreSQL startup refused")
        self.identity = self.inspect()
        image_platform = (
            self.command("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", self.declaration.image)
            .decode()
            .strip()
        )
        _need(image_platform == self.declaration.platform)
        image_id = self.command("image", "inspect", "--format", "{{.Id}}", self.declaration.image).decode().strip()
        _need(self.identity[0] == self.container and self.identity[1] == image_id)
        _need(self.identity[3] is True and self.identity[5] == 0 and self.identity[6] == "none")
        _need(not self.identity[7] and all(v is None for v in (self.identity[8] or {}).values()))
        _need(self.identity[10] == list(self.args) and self.identity[11] == f"{os.getuid()}:{os.getgid()}")
        _need(self.identity[12:14] == (False, True))
        _need(set(self.identity[14]) == {"none"})
        mounts = self.identity[9]
        _need(len(mounts) == 3)
        _need(
            {(m["Type"], m["Source"], m["Destination"], m["RW"]) for m in mounts}
            == {
                ("bind", str(self.home / "socket"), "/var/run/postgresql", True),
                ("bind", str(self.home / "data"), "/var/lib/postgresql/data", True),
                ("bind", str(self.home / "control"), "/academy-control", False),
            }
        )
        # The official entrypoint chmods this directory 03775 during setup.
        # Its ancestor stays private0700 throughout; seal before connections.
        (self.home / "socket").chmod(0o700)
        socket = self.home / "socket/.s.PGSQL.5432"
        info = socket.lstat()
        _need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        self.socket_identity = (info.st_dev, info.st_ino)
        self.configuration = tuple(
            (self.home / "data" / name, (self.home / "data" / name).read_bytes())
            for name in ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf")
        )
        self._arm_watch()
        self.logs = self._server_logs()
        self.events = self._events()
        _need(tuple(line.split()[0] for line in self.events[0]) == (b"create", b"start"))
        _need(len(self.events[1]) <= 1)
        _need(
            all(
                line.split()[:3]
                == [b"connect", self.identity[14]["none"]["NetworkID"].encode(), cast(str, self.container).encode()]
                for line in self.events[1]
            )
        )
        self.control_engine = self._engine("postgres")
        self.control = self._connect(self.control_engine).execution_options(isolation_level="AUTOCOMMIT")
        self.system = self.control.execute(
            sa.text("SELECT system_identifier::text FROM pg_catalog.pg_control_system()")
        ).scalar_one()
        self.postmaster = self.control.scalar(sa.text("SELECT pg_catalog.pg_postmaster_start_time()"))
        # CREATE all separately named databases from predeclaration, before any
        # profile observation. Identifiers are bounded above, never SQL-derived.
        for _, pairs in self.declaration.purposes:
            database = dict(pairs)["target_database"]
            self.control.exec_driver_sql(f'CREATE DATABASE "{database}" OWNER postgres TEMPLATE template0')
        for name in ("app_admin", *_RUNTIME):
            inherit = "NOINHERIT" if name == "academy_lab_worker" else "INHERIT"
            bypass = "BYPASSRLS" if name in ("app_admin", "academy_lab_worker") else "NOBYPASSRLS"
            self.control.exec_driver_sql(
                f'CREATE ROLE "{name}" LOGIN {inherit} {bypass} '
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD NULL"
            )
        for _, pairs in self.declaration.purposes:
            database = dict(pairs)["target_database"]
            self.control.exec_driver_sql(f'ALTER DATABASE "{database}" OWNER TO app_admin')
            engine = self._engine(cast(str, database))
            try:
                with self._connect(engine).execution_options(isolation_level="AUTOCOMMIT") as bootstrap:
                    bootstrap.exec_driver_sql("GRANT ALL ON SCHEMA public TO app_admin")
            finally:
                engine.dispose()
        self.engine = self._engine(cast(str, self.expected["target_database"]))
        self._live()

    def _engine(self, database: str) -> Engine:
        # No DSN is accepted or returned, no runtime role can authenticate.
        url = sa.URL.create("postgresql+psycopg", username="postgres", password=self.secret.decode(), database=database)
        return sa.create_engine(
            url,
            connect_args={"host": str(cast(Path, self.home) / "socket"), "connect_timeout": 5},
            poolclass=NullPool,
            hide_parameters=True,
            echo=False,
        )

    def _connect(self, engine: Engine) -> Connection:
        connection = engine.connect()
        try:
            pid, started = connection.execute(
                sa.text(
                    "SELECT pid,backend_start FROM pg_catalog.pg_stat_activity WHERE pid=pg_catalog.pg_backend_pid()"
                )
            ).one()
            _need(pid not in self.backends)
            self.backends[pid] = started
            connection.rollback()
            return connection
        except BaseException:
            connection.close()
            raise

    def _server_logs(self):
        result = subprocess.run(  # noqa: S603 - bounded owner-only server diagnostics, never emitted
            (self.docker, "logs", cast(str, self.container)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        _need(len(result.stdout) <= 1048576)
        return result.stdout

    def _events(self) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
        # Docker retains only 256 historical events. Initial create/start are
        # mandatory sentinels: eviction/loss can never reset our baseline.
        # Container filtering does NOT match network Actor.Attributes.container;
        # query that object type separately and emit only our exact container.
        # Never emit exec argv, labels, environment or unrelated network facts.
        end = str(time.time())
        since = self.identity[2]
        projected = (
            '{{if eq .Action "create"}}create{{else if eq .Action "start"}}start'
            "{{else}}changed{{end}} {{.Actor.ID}} {{.TimeNano}}"
        )
        containers = self.command(
            "events",
            "--since",
            since,
            "--until",
            end,
            "--filter",
            "container=" + cast(str, self.container),
            "--format",
            projected,
        )
        network_projection = (
            '{{if eq (index .Actor.Attributes "container") "' + cast(str, self.container) + '"}}'
            '{{.Action}} {{.Actor.ID}} {{index .Actor.Attributes "container"}} {{.TimeNano}}{{end}}'
        )
        networks = self.command(
            "events",
            "--since",
            since,
            "--until",
            end,
            "--filter",
            "type=network",
            "--format",
            network_projection,
        )
        network_events = tuple(line for line in networks.splitlines() if line.strip())
        for line in network_events:
            fields = line.split()
            _need(len(fields) == 4)
            action, network_id, container_id, timestamp = fields
            _need(re.fullmatch(rb"[a-z_]+", action) is not None)
            _need(re.fullmatch(rb"[a-f0-9]{64}", network_id) is not None)
            _need(container_id == cast(str, self.container).encode("ascii"))
            _need(timestamp.isdigit() and int(timestamp) > 0)
        return (
            tuple(line for line in containers.splitlines() if line.strip()),
            network_events,
        )

    def _arm_watch(self):
        # Kernel event queue records repaired chmod/rename/write drift, unlike
        # snapshots. Queue overflow, watch loss, or any change poisons forever.
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        _need(fd >= 0)
        self.watch = fd
        mask = 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800
        for ordinal, path in enumerate(
            (
                cast(Path, self.home),
                cast(Path, self.home) / "control",
                cast(Path, self.home) / "socket",
                cast(Path, self.home) / "data",
                self.hba,
                self.password,
                *(p for p, _ in self.configuration),
            ),
            1,
        ):
            descriptor = libc.inotify_add_watch(fd, os.fsencode(path), mask)
            _need(descriptor >= 0)
            self._watch_descriptors[descriptor] = 0 if descriptor in self._watch_descriptors else ordinal

    def _fatal_watch_event(self):
        self.poisoned = True
        self._watch_event = None
        try:
            self._watch_event = _first_watch_event(os.read(cast(int, self.watch), 4096), self._watch_descriptors)
        except Exception:
            self._watch_event = None
        raise HostedGenesisRefused("Hosted resource watch refused") from None

    def _live(self):
        _need(not self.poisoned and os.getpid() == self.pid)
        if select.select([cast(int, self.watch)], [], [], 0)[0]:
            self._fatal_watch_event()
        _require_container_identity(self.inspect(), self.identity)
        _need(all(not path.is_symlink() and path.read_bytes() == data for path, data in self.configuration))
        _need(_private_directory(cast(Path, self.home)) == self.home_identity)
        for name, identity in self.dirs.items():
            _need(_private_directory(cast(Path, self.home) / name) == identity)
        _need((_private_file(self.hba, _HBA.encode()), _private_file(self.password, self.secret)) == self.file_ids)
        socket = (cast(Path, self.home) / "socket/.s.PGSQL.5432").lstat()
        _need(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == os.getuid() and stat.S_IMODE(socket.st_mode) == 0o700)
        _need((socket.st_dev, socket.st_ino) == self.socket_identity)
        _need(self._events() == self.events)
        logs = self._server_logs()
        _need(logs.startswith(self.logs))
        authentications: dict[tuple[int, bytes], int] = {}
        for line in logs[len(self.logs) :].splitlines():
            # Failed authentication is unexpected access too. Logs never leave
            # the owner and statements are disabled at PostgreSQL itself.
            if b"connection authorized:" in line or b"connection authenticated:" in line:
                match = re.match(rb"([0-9]+) ", line)
                _need(match is not None and int(match[1]) in self.backends)
                kind = b"authorized" if b"connection authorized:" in line else b"authenticated"
                key = (int(cast(re.Match[bytes], match)[1]), kind)
                authentications[key] = authentications.get(key, 0) + 1
                _need(authentications[key] == 1)
            _need(b"FATAL:" not in line and b"PANIC:" not in line)
        # Keep original prefix so disappearance/truncation cannot reset audit.
        _need(
            cast(Connection, self.control).scalar(
                sa.text("SELECT system_identifier::text FROM pg_catalog.pg_control_system()")
            )
            == self.system
        )
        _need(
            cast(Connection, self.control).scalar(sa.text("SELECT pg_catalog.pg_postmaster_start_time()"))
            == self.postmaster
        )
        rows = (
            cast(Connection, self.control)
            .execute(
                sa.text("SELECT pid,backend_start FROM pg_catalog.pg_stat_activity WHERE backend_type='client backend'")
            )
            .all()
        )
        _need(all(self.backends.get(pid) == started for pid, started in rows))
        _need(cast(Connection, self.control).scalar(sa.text("SELECT count(*) FROM pg_catalog.pg_prepared_xacts")) == 0)
        _need(
            cast(Connection, self.control).scalar(sa.text("SELECT count(*) FROM pg_catalog.pg_replication_slots")) == 0
        )
        _need(cast(Connection, self.control).scalar(sa.text("SELECT count(*) FROM pg_catalog.pg_subscription")) == 0)
        # pg_roles masks every password as ********, including absent ones.
        # Only the owned privileged control channel may inspect this boolean;
        # password material never leaves PostgreSQL.
        _need(
            cast(Connection, self.control).scalar(
                sa.text(
                    "SELECT count(*) FROM pg_catalog.pg_authid "
                    "WHERE rolname = ANY(:roles) AND rolpassword IS NOT NULL"
                ),
                {"roles": list(_RUNTIME)},
            )
            == 0
        )
        _need(cast(Connection, self.control).scalar(sa.text("SELECT current_setting('listen_addresses')")) == "")
        rules = (
            cast(Connection, self.control)
            .execute(
                sa.text(
                    "SELECT type,database,user_name,address,auth_method,error "
                    "FROM pg_catalog.pg_hba_file_rules ORDER BY rule_number"
                )
            )
            .all()
        )
        _need(
            tuple(tuple(r) for r in rules)
            == (
                ("local", ["all"], ["postgres"], None, "scram-sha-256", None),
                ("local", ["all"], ["all"], None, "reject", None),
                ("host", ["all"], ["all"], "all", "reject", None),
            )
        )
        if select.select([cast(int, self.watch)], [], [], 0)[0]:
            self._fatal_watch_event()

    @contextmanager
    def replay_connection(self) -> Iterator[Connection]:
        _need(not self.sealed and self.connection is None)
        try:
            self._live()
            with self._connect(cast(Engine, self.engine)) as connection:
                connection.exec_driver_sql("SET ROLE app_admin")
                connection.commit()  # bootstrap only: never the coordinator root
                yield connection
                _need(not connection.in_transaction())
            self._live()
            self.replayed = True
        except BaseException:
            self.poisoned = True
            raise

    @contextmanager
    def coordinator_connection(self) -> Iterator[Connection]:
        _need(not self.sealed and self.connection is None and self.replayed)
        self.sealed = True
        try:
            self._live()
            self.connection = self._connect(cast(Engine, self.engine))
            self.connection.exec_driver_sql("SET ROLE app_admin")
            self.connection.commit()  # before caller can begin its sole root
            yield self.connection
        except BaseException:
            self.poisoned = True
            raise
        finally:
            # Never implicitly rollback an active caller-owned root via close.
            if self.connection is not None and self.connection.in_transaction():
                self.poisoned = True
                raise HostedGenesisRefused("Coordinator must finish its own root before owner cleanup")
            if self.connection is not None:
                self.connection.close()
                self.connection = None

    def bind_root(self, connection: Connection):
        try:
            self._live()
            _need(connection is self.connection and not connection.closed)
            root = connection.get_transaction()
            _need(root is not None and root.is_active and connection.get_nested_transaction() is None)
            _need(self.root is None)
            self.root = root

            # Passive event witnesses retain evidence of even repaired wrapper
            # root/savepoint drift. They never manage the coordinator root.
            def lose_continuity(*_args):
                self.poisoned = True

            for event_name in ("commit", "rollback", "savepoint", "begin"):
                sa.event.listen(connection, event_name, lose_continuity)
                self.root_listeners.append((connection, event_name, lose_continuity))
            self.xid = connection.scalar(sa.text("SELECT pg_catalog.pg_current_xact_id()::text"))
            # Non-secret transient backend challenge, independently observed by
            # the separate owned channel; no persistent marker/schema mutation.
            challenge = "academy-genesis-" + secrets.token_hex(16)
            connection.execute(
                sa.text("SELECT pg_catalog.set_config('application_name',:challenge,true)"), {"challenge": challenge}
            )
            pid = connection.scalar(sa.text("SELECT pg_catalog.pg_backend_pid()"))
            observed = (
                cast(Connection, self.control)
                .execute(
                    sa.text(
                        "SELECT datname,application_name,backend_xid::text "
                        "FROM pg_catalog.pg_stat_activity WHERE pid=:pid"
                    ),
                    {"pid": pid},
                )
                .one()
            )
            _need(
                tuple(observed)
                == (self.expected["target_database"], challenge, str(int(cast(str, self.xid)) % (2**32)))
            )
            self.backend = pid
            self.challenge = challenge
            handle = object.__new__(_Handle)
            _ISSUED[handle] = self
            self.verify(connection, self.expected)
            return handle
        except BaseException:
            self.poisoned = True
            raise

    def verify(self, connection: Connection, bindings: Mapping[str, object] | tuple[tuple[str, object], ...]) -> None:
        try:
            self._live()
            _need(
                connection is self.connection
                and connection.get_transaction() is self.root
                and cast(RootTransaction, self.root).is_active
            )
            _need(not connection.closed and not connection.invalidated and connection.get_nested_transaction() is None)
            _need(dict(bindings) == self.expected)
            result = connection.execute(
                sa.text(
                    "SELECT current_database(),session_user,current_user,pg_catalog.pg_backend_pid(),"
                    "pg_catalog.pg_current_xact_id()::text,pg_catalog.pg_postmaster_start_time(),"
                    "current_setting('application_name')"
                )
            ).one()
            _need(
                tuple(result)
                == (
                    self.expected["target_database"],
                    "postgres",
                    "app_admin",
                    self.backend,
                    self.xid,
                    self.postmaster,
                    self.challenge,
                )
            )
            observed = (
                cast(Connection, self.control)
                .execute(
                    sa.text(
                        "SELECT datname,application_name,backend_xid::text "
                        "FROM pg_catalog.pg_stat_activity WHERE pid=:pid"
                    ),
                    {"pid": self.backend},
                )
                .one()
            )
            _need(
                tuple(observed)
                == (self.expected["target_database"], self.challenge, str(int(cast(str, self.xid)) % (2**32)))
            )
        except BaseException as error:
            self.poisoned = True
            if not isinstance(error, Exception):
                raise
            raise HostedGenesisRefused("Hosted resource continuity refused; root rollback required") from None

    def close(self):
        self.poisoned = True
        failures = []
        if self.control is not None:
            try:
                self.control.close()
            except BaseException as error:
                failures.append(error)
        for engine in (self.engine, self.control_engine):
            if engine is not None:
                try:
                    engine.dispose()
                except BaseException as error:
                    failures.append(error)
        # No commit/rollback/close of the coordinator's active connection.
        # Destroying this disposable server is cleanup, never successful adoption.
        try:
            if self.container is not None:
                self.command("rm", "--force", "--volumes", self.container)
            elif self.home is not None:
                # Create may have succeeded before interruption delivered output.
                found = self.command(
                    "ps", "--all", "--quiet", "--no-trunc", "--filter", "name=^/" + self.name + "$"
                ).strip()
                if found:
                    _need(bool(re.fullmatch(rb"[a-f0-9]{64}", found)))
                    self.command("rm", "--force", "--volumes", found.decode())
        except BaseException as error:
            failures.append(error)
        for connection, event_name, listener in self.root_listeners:
            sa.event.remove(connection, event_name, listener)
        self.root_listeners.clear()
        if self.watch is not None:
            os.close(self.watch)
        if self.home is not None and not failures:
            try:
                _need(_private_directory(self.home) == self.home_identity)
                shutil.rmtree(self.home)
            except BaseException as error:
                failures.append(error)
        self.secret = b""
        if failures:
            raise HostedGenesisRefused("Hosted resource cleanup failed; job must fail") from None


def _watch_diagnostic(owner):
    if type(owner) is not _Owner or owner.poisoned is not True:
        return ""
    event = getattr(owner, "_watch_event", None)
    if type(event) is not tuple or len(event) != 4:
        return ""
    ordinal, name_class, mask, unknown = event
    if not (
        type(ordinal) is int
        and 0 <= ordinal <= 10
        and type(name_class) is int
        and 0 <= name_class <= 12
        and type(mask) is int
        and 0 <= mask <= _WATCH_MASK
        and not mask & ~_WATCH_MASK
        and type(unknown) is bool
    ):
        return ""
    return f" [watch event=1 object={ordinal} name={name_class} mask={mask:08x} unknown={int(unknown)}]"


def _verify_context(context: object, connection: Connection, bindings: object) -> None:
    if type(context) is not _Handle or context not in _ISSUED:
        _poison_context(context, connection)
        raise HostedGenesisRefused("Unissued hosted resource context refused")
    owner = _ISSUED[context]
    try:
        pairs = tuple((name, getattr(bindings, name)) for name in _FIELDS)
        owner.verify(connection, pairs)
    except BaseException as error:
        owner.poisoned = True
        if not isinstance(error, Exception):
            raise
        try:
            from app.maintenance.product_adoption import _maintenance_refusal_locations

            location = _maintenance_refusal_locations(error)
        except Exception:
            location = "unavailable"
        try:
            watch = _watch_diagnostic(owner)
        except Exception:
            watch = ""
        raise HostedGenesisRefused(f"Hosted resource context refused [maintenance {location}]{watch}") from None


def _poison_context(context: object, connection: Connection | None = None) -> None:
    if type(context) is _Handle and context in _ISSUED:
        _ISSUED[context].poisoned = True
    # A forged/missing context cannot leave this actual owned connection usable
    # after the consumer has refused it. No caller-supplied association is used.
    for owner in list(_ISSUED.values()):
        if connection is not None and owner.connection is connection:
            owner.poisoned = True


@contextmanager
def disposable_genesis(declaration: HostedGenesisDeclaration, *, purpose: str) -> Iterator[_Owner]:
    """CREATE fresh resource. Root alone runs this on the hosted authority.

    Exposes only owned bootstrap/coordinator connections and root binding;
    private owner attributes are implementation details, never admission APIs.
    """
    owner = _Owner(declaration, purpose)
    try:
        owner.setup()
        yield owner
    finally:
        owner.close()
