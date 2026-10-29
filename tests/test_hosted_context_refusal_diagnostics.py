"""Pure context-boundary diagnostics; never create a resource or connection."""

import re
import traceback
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import product_adoption as product
from app.maintenance import retained_hosted_genesis as hosted


@pytest.mark.parametrize("kind", ["ordinary", "keyboard", "exit"])
def test_context_refusal_poisoning_precedes_safe_diagnostic(monkeypatch, capsys, kind):
    marker = "PRIVATE_HOSTED_CONTEXT_SENTINEL"
    interrupt = {"keyboard": KeyboardInterrupt, "exit": SystemExit}.get(kind)
    failure = interrupt(marker) if interrupt else RuntimeError(marker)
    handle = object.__new__(hosted._Handle)
    connection = object()
    values = {field: object() for field in hosted._FIELDS}
    bindings = SimpleNamespace(**values)
    events = []

    def verify(actual, pairs):
        assert actual is connection and dict(pairs) == values
        events.append("verify")
        if interrupt:
            raise failure
        try:
            hosted._need(False)
        except hosted.HostedGenesisRefused:
            # The existing helper must follow this suppressed owned context
            # without rendering the private outer exception message.
            raise failure from None

    owner = SimpleNamespace(poisoned=False, verify=verify)
    real_locations = product._maintenance_refusal_locations

    def locations(error):
        assert error is failure and owner.poisoned and events == ["verify"]
        events.append("diagnostic")
        return real_locations(error)

    monkeypatch.setitem(hosted._ISSUED, handle, owner)
    monkeypatch.setattr(product, "_maintenance_refusal_locations", locations)
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    expected = interrupt or hosted.HostedGenesisRefused
    with pytest.raises(expected) as refused:
        hosted._verify_context(handle, connection, bindings)
    assert owner.poisoned
    if interrupt:
        assert refused.value is failure and events == ["verify"]
    else:
        assert type(refused.value) is hosted.HostedGenesisRefused
        assert events == ["verify", "diagnostic"]
        assert refused.value.__suppress_context__ is True and refused.value.__cause__ is None
        assert re.fullmatch(
            r"Hosted resource context refused \[maintenance "
            r"retained_hosted_genesis\.py:\d+(?: > retained_hosted_genesis\.py:\d+){0,3}\]",
            str(refused.value),
        )
        assert marker not in "".join(traceback.format_exception(refused.value))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_unissued_context_refuses_without_diagnostic_or_resource(monkeypatch):
    monkeypatch.setattr(
        product, "_maintenance_refusal_locations", lambda *a: pytest.fail("no issued context diagnostic")
    )
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    with pytest.raises(hosted.HostedGenesisRefused, match="^Unissued hosted resource context refused$"):
        hosted._verify_context(object(), object(), object())


def test_diagnostic_failure_preserves_hosted_refusal_and_redaction(monkeypatch):
    handle = object.__new__(hosted._Handle)

    def fail(*args):
        raise RuntimeError("PRIVATE_DIAGNOSTIC_FAILURE_SENTINEL")

    owner = SimpleNamespace(poisoned=False, verify=fail)
    monkeypatch.setitem(hosted._ISSUED, handle, owner)
    monkeypatch.setattr(product, "_maintenance_refusal_locations", fail)
    bindings = SimpleNamespace(**{field: object() for field in hosted._FIELDS})
    with pytest.raises(hosted.HostedGenesisRefused) as refused:
        hosted._verify_context(handle, object(), bindings)
    assert owner.poisoned and refused.value.__suppress_context__ is True
    assert str(refused.value) == "Hosted resource context refused [maintenance unavailable]"
    assert "SENTINEL" not in "".join(traceback.format_exception(refused.value))


@pytest.fixture(autouse=True)
def no_actual_resources(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        pytest.fail("pure watch tests cannot acquire sockets/processes/inotify/DB or read OS descriptors")

    monkeypatch.setattr(Engine, "connect", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(hosted.ctypes, "CDLL", forbidden)
    monkeypatch.setattr(hosted.subprocess, "run", forbidden)
    monkeypatch.setattr(hosted.subprocess, "Popen", forbidden)
    monkeypatch.setattr(hosted.os, "read", forbidden)
    monkeypatch.setattr(hosted.select, "select", forbidden)


def _watch_owner():
    owner = object.__new__(hosted._Owner)
    owner.poisoned, owner.pid, owner.watch = False, hosted.os.getpid(), 71
    owner._watch_event, owner._watch_descriptors = None, {3: 3}
    return owner


def _watch_record(*, wd=3, mask=4, name=b"", cookie=0, length=None):
    import struct

    return struct.pack("=iIII", wd, mask, cookie, len(name) if length is None else length) + name


@pytest.mark.parametrize("bit", [bit for bit in range(32) if (1 << bit) & 0x4000EFFF])
def test_each_known_native_mask_bit_is_metadata_only_and_always_fatal(monkeypatch, bit):
    owner = _watch_owner()
    calls = []

    def read(fd, count):
        assert owner.poisoned is True and (fd, count) == (71, 4096)
        calls.append(True)
        return _watch_record(mask=1 << bit)

    monkeypatch.setattr(hosted.os, "read", read)
    with pytest.raises(hosted.HostedGenesisRefused, match="^Hosted resource watch refused$") as raised:
        owner._fatal_watch_event()
    assert raised.value.__suppress_context__
    assert calls == [True] and owner._watch_event == (3, 1, 1 << bit, False)


@pytest.mark.parametrize(
    "name,code",
    [
        (b"", 1),
        (b"control", 2),
        (b"socket", 3),
        (b"data", 4),
        (b"hba", 5),
        (b"password", 6),
        (b"postgresql.conf", 7),
        (b"postgresql.auto.conf", 8),
        (b"pg_hba.conf", 9),
        (b"pg_ident.conf", 10),
        (b".s.PGSQL.5432", 11),
        (b".s.PGSQL.5432.lock", 12),
        (b"PRIVATE_UNKNOWN_NAME", 0),
        (b"\xff\xfe", 0),
    ],
)
def test_native_name_classification_never_decodes_or_retains_names(name, code):
    payload = _watch_record(name=name + b"\0\0\0", cookie=0xDEADBEEF)
    assert hosted._first_watch_event(payload, {3: 10}) == (10, code, 4, False)


@pytest.mark.parametrize(
    "wd,mask,expected",
    [
        (-1, 0x4000, (0, 1, 0x4000, False)),
        (99, 0x8000, (0, 1, 0x8000, False)),
        (3, 0x1000, (3, 1, 0, True)),
        (3, 0x80000004, (3, 1, 4, True)),
    ],
)
def test_unknown_descriptor_overflow_watch_loss_and_unknown_bits_are_bounded(wd, mask, expected):
    assert hosted._first_watch_event(_watch_record(wd=wd, mask=mask), {3: 3}) == expected


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"x" * 15,
        b"x" * 4097,
        bytearray(b"x" * 16),
        _watch_record(name=b"bad", length=100),
        _watch_record(name=b"noNUL"),
        _watch_record(name=b"name\0x"),
        _watch_record(length=0xFFFFFFFF),
    ],
)
def test_malformed_first_record_refuses_without_rendering_payload(payload):
    with pytest.raises(hosted.HostedGenesisRefused):
        hosted._first_watch_event(payload, {3: 3})


def test_only_first_record_is_inspected_even_with_unknown_later_record():
    first = _watch_record(mask=4, name=b"socket\0\0")
    assert hosted._first_watch_event(first + b"PRIVATE_MALFORMED_TRAILING_RECORD", {3: 3}) == (3, 3, 4, False)
    assert hosted._first_watch_event(_watch_record() + _watch_record(mask=0x80000000), {3: 3}) == (3, 1, 4, False)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("PRIVATE_READ_FAILURE"),
        RuntimeError("PRIVATE_READ_FAILURE"),
        KeyboardInterrupt("PRIVATE_CANCEL"),
        SystemExit("PRIVATE_CANCEL"),
    ],
)
def test_single_read_failure_or_cancellation_cannot_undo_poison(monkeypatch, failure):
    owner = _watch_owner()
    count = []

    def read(fd, size):
        assert owner.poisoned
        count.append(True)
        raise failure

    monkeypatch.setattr(hosted.os, "read", read)
    expected = type(failure) if not isinstance(failure, Exception) else hosted.HostedGenesisRefused
    with pytest.raises(expected) as raised:
        owner._fatal_watch_event()
    if not isinstance(failure, Exception):
        assert raised.value is failure
    else:
        assert "PRIVATE" not in "".join(traceback.format_exception(raised.value))
    assert owner.poisoned and owner._watch_event is None and count == [True]


@pytest.mark.parametrize(
    "event",
    [
        (True, 1, 4, False),
        (1, True, 4, False),
        (1, 1, True, False),
        (1, 1, 4, 1),
        (-1, 1, 4, False),
        (11, 1, 4, False),
        (1, 13, 4, False),
        (1, 1, 0x1000, False),
        (1, 1, -1, False),
        [1, 1, 4, False],
        None,
        (1, 1, 4),
    ],
)
def test_malicious_or_nonnative_metadata_never_formats(event):
    owner = _watch_owner()
    owner.poisoned, owner._watch_event = True, event
    assert hosted._watch_diagnostic(owner) == ""
    assert hosted._watch_diagnostic(SimpleNamespace(poisoned=True, _watch_event=(1, 1, 4, False))) == ""


def test_safe_optional_suffix_requires_actual_poisoned_owner_and_hides_token(monkeypatch, capsys):
    owner = _watch_owner()
    handle = object.__new__(hosted._Handle)
    monkeypatch.setitem(hosted._ISSUED, handle, owner)
    monkeypatch.setattr(hosted.os, "read", lambda *a: _watch_record(name=b".s.PGSQL.5432.lock\0", cookie=0xDEADBEEF))
    owner.verify = lambda *a: owner._fatal_watch_event()
    bindings = SimpleNamespace(**{field: object() for field in hosted._FIELDS})
    assert hosted._watch_diagnostic(owner) == ""
    with pytest.raises(hosted.HostedGenesisRefused) as raised:
        hosted._verify_context(handle, object(), bindings)
    assert str(raised.value).endswith("[watch event=1 object=3 name=12 mask=00000004 unknown=0]")
    assert "5432" not in str(raised.value) and "DEADBEEF" not in str(raised.value)
    assert raised.value.__suppress_context__
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_actual_arm_preserves_paths_mask_and_permanent_duplicate_descriptor_zero(monkeypatch):
    from pathlib import Path

    owner = _watch_owner()
    owner._watch_descriptors = {}
    owner.home = Path("/PRIVATE_SYNTHETIC_HOME")
    owner.hba, owner.password = owner.home / "control/hba", owner.home / "control/password"
    owner.configuration = tuple(
        (owner.home / "data" / name, b"")
        for name in ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf")
    )
    paths, masks = [], []
    descriptors = iter([9, 9, 9, 10, 11, 12, 13, 14, 15, 16])

    def add(fd, path, mask):
        assert fd == 71
        paths.append(path)
        masks.append(mask)
        return next(descriptors)

    def initialize(flags):
        assert flags == hosted.os.O_NONBLOCK | hosted.os.O_CLOEXEC
        return 71

    monkeypatch.setattr(
        hosted.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(inotify_init1=initialize, inotify_add_watch=add)
    )
    owner._arm_watch()
    assert len(paths) == 10 and masks == [0xFCE] * 10
    assert owner._watch_descriptors == {9: 0, 10: 4, 11: 5, 12: 6, 13: 7, 14: 8, 15: 9, 16: 10}
    assert paths == [
        hosted.os.fsencode(path)
        for path in (
            owner.home,
            owner.home / "control",
            owner.home / "socket",
            owner.home / "data",
            owner.hba,
            owner.password,
            *(p for p, _ in owner.configuration),
        )
    ]


def _live_owner_without_resources(monkeypatch):
    owner = _watch_owner()

    class Directory:
        def __truediv__(self, name):
            return self

        def lstat(self):
            return SimpleNamespace(st_mode=hosted.stat.S_IFSOCK | 0o700, st_uid=1, st_dev=1, st_ino=2)

    owner.home = Directory()
    owner.configuration, owner.dirs, owner.home_identity = (), {}, 1
    owner.hba, owner.password, owner.secret, owner.file_ids = object(), object(), b"synthetic", (0, 0)
    owner.socket_identity, owner.identity = (1, 2), object()
    owner.inspect = lambda: owner.identity
    owner.events, owner.logs, owner.backends, owner.system, owner.postmaster = ((), ()), b"", {}, "system", "start"
    owner._events, owner._server_logs = lambda: owner.events, lambda: b""
    monkeypatch.setattr(hosted.os, "getuid", lambda: 1)
    monkeypatch.setattr(hosted, "_require_container_identity", lambda *a: None)
    monkeypatch.setattr(hosted, "_private_directory", lambda *a: 1)
    monkeypatch.setattr(hosted, "_private_file", lambda *a: 0)

    def scalar(query, *a):
        text = str(query)
        if "system_identifier" in text:
            return "system"
        if "postmaster_start_time" in text:
            return "start"
        if "listen_addresses" in text:
            return ""
        assert "count(*)" in text
        return 0

    def execute(query):
        if "pg_stat_activity" in str(query):
            return SimpleNamespace(all=lambda: ())
        assert "pg_hba_file_rules" in str(query)
        rows = (
            ("local", ["all"], ["postgres"], None, "scram-sha-256", None),
            ("local", ["all"], ["all"], None, "reject", None),
            ("host", ["all"], ["all"], "all", "reject", None),
        )
        return SimpleNamespace(all=lambda: rows)

    owner.control = SimpleNamespace(scalar=scalar, execute=execute)
    return owner


@pytest.mark.parametrize("readiness_site", [1, 2])
def test_both_real_live_readiness_sites_poison_before_one_read_and_never_resume(monkeypatch, readiness_site):
    owner = _live_owner_without_resources(monkeypatch)
    selects, reads = [], []

    def readiness(read, write, error, timeout):
        assert (read, write, error, timeout) == ([71], [], [], 0)
        selects.append(True)
        return ([71] if len(selects) == readiness_site else [], [], [])

    def read(fd, count):
        assert owner.poisoned and (fd, count) == (71, 4096)
        reads.append(True)
        return _watch_record(name=b"PRIVATE_RAW_FILENAME\0", cookie=0x12345678)

    monkeypatch.setattr(hosted.select, "select", readiness)
    monkeypatch.setattr(hosted.os, "read", read)
    with pytest.raises(hosted.HostedGenesisRefused):
        owner._live()
    assert len(selects) == readiness_site and reads == [True] and owner._watch_event == (3, 0, 4, False)
    with pytest.raises(hosted.HostedGenesisRefused):
        owner._live()
    assert len(selects) == readiness_site and reads == [True]


def test_invalid_parser_data_leaves_only_unavailable_metadata_and_fatal_poison(monkeypatch):
    owner = _watch_owner()
    monkeypatch.setattr(hosted.os, "read", lambda *a: b"PRIVATE_SHORT")
    with pytest.raises(hosted.HostedGenesisRefused):
        owner._fatal_watch_event()
    assert owner.poisoned and owner._watch_event is None and hosted._watch_diagnostic(owner) == ""


def test_invalid_metadata_objects_are_never_rendered_or_compared():
    class PrivateValue:
        def __str__(self):
            pytest.fail("private diagnostic object rendered")

        __repr__ = __str__

        def __eq__(self, other):
            pytest.fail("private diagnostic object compared")

    owner = _watch_owner()
    owner.poisoned, owner._watch_event = True, (PrivateValue(), 1, 4, False)
    assert hosted._watch_diagnostic(owner) == ""
    owner._watch_event = (1, PrivateValue(), 4, False)
    assert hosted._watch_diagnostic(owner) == ""
    owner._watch_event = (1, 1, PrivateValue(), False)
    assert hosted._watch_diagnostic(owner) == ""
    owner._watch_event = (1, 1, 4, PrivateValue())
    assert hosted._watch_diagnostic(owner) == ""
