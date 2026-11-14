# ruff: noqa: S101 -- hosted synthetic filesystem qualification; never real host inputs.
"""Canonical parent eligibility precedes source/dependency target leaf access."""

import os

import candidate_authority_discovery as D
import pytest
from test_systemd_effective_definitions import acquire, validate
from test_systemd_template_definitions import LOW, ROOT, SyntheticDefinitions, SyntheticFS, domain, facts, relations

ALIAS = "/lib/systemd/system"


class PathAwareFS(SyntheticFS):
    def __init__(self):
        super().__init__()
        self.accesses = []
        self.before_access = None

    def syscall(self, operation, *args, **kwargs):
        if operation in ("close", "fstat", "read", "scandir"):
            path = self.fds[args[0]]["node"]["path"]
        else:
            path = self.fullpath(args[0], kwargs.get("dir_fd"))
        self.accesses.append((operation, path))
        if self.before_access is not None:
            self.before_access(operation, path)
        return super().syscall(operation, *args, **kwargs)


def primed(filesystem, active=(LOW,)):
    discovery = SyntheticDefinitions(filesystem, roots=active)
    discovery.definition_state()["active_roots"] = active
    return discovery


def selected(filesystem, path, physical):
    return {"path": path, "metadata": {"identity": D.Discovery.file_identity(
        filesystem.metadata(filesystem.nodes[physical]))}}


def visit(discovery, caller, path, physical):
    if caller == "source":
        return discovery.definition_source_object(selected(discovery.fs, path, physical))
    return discovery.definition_dependency_mask(path)


def assert_leaf_untouched(filesystem, leaf):
    assert not [(operation, path) for operation, path in filesystem.accesses
                if path == leaf and operation in ("stat", "open", "read", "readlink")]


def alias_fs(body=b"[Unit]\n"):
    filesystem = PathAwareFS()
    filesystem.add(LOW + "/generic.service", data=body)
    filesystem.add("/lib", "symlink", "usr/lib")
    return filesystem


def test_selected_dropin_alias_reads_canonical_body_twice_with_unchanged_unknown_authority():
    filesystem = alias_fs()
    filesystem.add(ROOT + "/plain.service", data=b"[Unit]\n")
    filesystem.add(LOW + "/snippet.conf", data=b"[Unit]\nRequires=dependency.service\n")
    filesystem.add(ROOT + "/plain.service.d/10.conf", "symlink", ALIAS + "/snippet.conf")
    discovery = acquire(filesystem, installed=("plain.service",), roots=(ROOT, LOW))
    result = facts(discovery, "plain.service")
    assert result["source_acquisition_complete"] and domain(discovery)["enumeration_complete"]
    assert [(path, count) for path, count in filesystem.reads if path == LOW + "/snippet.conf"] == [
        (LOW + "/snippet.conf", len(filesystem.nodes[LOW + "/snippet.conf"]["data"])),
        (LOW + "/snippet.conf", len(filesystem.nodes[LOW + "/snippet.conf"]["data"])),
    ]
    assert [row["value_sha256"] for row in relations(discovery, "plain.service")] == [D.digest(b"dependency.service")]
    assert result["classification"] == "unknown" and result["authority_refs"] == []
    assert not result["activation_semantics_complete"]
    assert not discovery.fs.fds
    report = validate(discovery)
    assert not report["coverage_complete"] and not report["classification_complete"]
    assert not report["campaign_authority_claimed"]
    assert report["resource_accounting"]["definition_filesystem_work"] == discovery.definition_files


@pytest.mark.parametrize("empty", [False, True], ids=["nonempty", "empty-mask"])
def test_dependency_alias_to_active_canonical_root_checks_metadata_without_reading_body(empty):
    filesystem = alias_fs(b"" if empty else b"opaque synthetic body")
    discovery = primed(filesystem)
    try:
        assert discovery.definition_dependency_mask(ALIAS + "/generic.service") is empty
        observations = domain(discovery)["path_observations"]
        assert any(row["kind"] == "dependency_target" for row in observations)
        assert filesystem.reads == []
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds


@pytest.mark.parametrize("caller", ["source", "dependency"])
def test_active_lexical_alias_cannot_reach_inactive_canonical_leaf(caller):
    filesystem = PathAwareFS()
    leaf = filesystem.add(LOW + "/generic.service", data=b"unread")
    filesystem.add(ROOT, "symlink", LOW)
    discovery = primed(filesystem, (ROOT,))
    try:
        with pytest.raises(D.DefinitionRefusedError, match="definition_linked_target_unprofiled"):
            visit(discovery, caller, ROOT + "/generic.service", leaf)
        assert_leaf_untouched(filesystem, leaf)
        assert filesystem.reads == []
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds


@pytest.mark.parametrize("caller", ["source", "dependency"])
@pytest.mark.parametrize("path", ["/opt/unprofiled/generic.service", "/lib/systemd/system/../generic.service",
                                  ALIAS])
def test_uncompiled_noncanonical_or_root_only_target_refuses_before_filesystem(caller, path):
    filesystem = alias_fs()
    discovery = primed(filesystem)
    try:
        with pytest.raises(D.DefinitionRefusedError, match="definition_linked_target_unprofiled"):
            visit(discovery, caller, path, LOW + "/generic.service")
        assert filesystem.accesses == []
    finally:
        discovery.definition_close_pass()


@pytest.mark.parametrize("caller", ["source", "dependency"])
def test_compiled_parent_alias_escape_keeps_original_walker_refusal_before_leaf(caller):
    filesystem = PathAwareFS()
    leaf = filesystem.add("/opt/unprofiled/generic.service", data=b"unread")
    filesystem.add("/lib", "symlink", "/opt/unprofiled")
    discovery = primed(filesystem, (ALIAS,))
    try:
        with pytest.raises(D.DefinitionRefusedError, match="definition_link_outside_profile"):
            visit(discovery, caller, ALIAS + "/generic.service", leaf)
        assert_leaf_untouched(filesystem, leaf)
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds


@pytest.mark.parametrize("caller", ["source", "dependency"])
@pytest.mark.parametrize("active", [False, True], ids=["inactive", "active"])
def test_missing_parent_preserves_only_lexically_active_absence_semantics(caller, active):
    filesystem = PathAwareFS()
    physical = filesystem.add(LOW + "/generic.service", data=b"unused identity")
    filesystem.add(ROOT, "directory")
    discovery = primed(filesystem, (ROOT,) if active else (LOW,))
    path = ROOT + "/missing/generic.service"
    try:
        if active and caller == "dependency":
            assert visit(discovery, caller, path, physical) is False
        else:
            code = "definition_selected_source_missing" if active else "definition_linked_target_unprofiled"
            with pytest.raises(D.DefinitionRefusedError, match=code):
                visit(discovery, caller, path, physical)
        assert_leaf_untouched(filesystem, path)
        assert filesystem.reads == []
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds


@pytest.mark.parametrize("caller", ["source", "dependency"])
@pytest.mark.parametrize("race", ["link-named", "parent-opened"])
def test_alias_parent_metadata_races_refuse_before_target_leaf(caller, race):
    filesystem = alias_fs()
    discovery = primed(filesystem)
    link_stats = []

    def mutate(operation, path):
        if race == "link-named" and operation == "stat" and path == "/lib":
            link_stats.append(True)
            if len(link_stats) == 2:
                filesystem.nodes[path]["stamp"] += 1
        if race == "parent-opened" and operation == "fstat" and path == LOW:
            filesystem.nodes[path]["stamp"] += 1

    filesystem.before_access = mutate
    try:
        with pytest.raises(D.DefinitionRefusedError, match="definition_snapshot_changed"):
            visit(discovery, caller, ALIAS + "/generic.service", LOW + "/generic.service")
        assert_leaf_untouched(filesystem, LOW + "/generic.service")
    finally:
        filesystem.before_access = None
        discovery.definition_close_pass()
    assert not filesystem.fds


@pytest.mark.parametrize("caller", ["source", "dependency"])
@pytest.mark.parametrize("stop", ["work", "cancel", "deadline"])
def test_parent_guard_stops_before_io_without_losing_reserved_cleanup(caller, stop):
    filesystem = alias_fs()
    discovery = primed(filesystem)
    state = discovery.definition_state()
    # Open one descriptor first: its prepaid cleanup remains usable after refusal.
    discovery.definition_open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if stop == "work":
        state["work"] = D.SYSTEMD_DEFINITION_PROFILE["filesystem_work"] - state["reserved_work"]
        discovery.files = discovery.definition_files = state["work"]
    elif stop == "cancel":
        discovery.pending_signal = 15
    else:
        discovery.deadline = 0
    before = len(filesystem.accesses)
    try:
        code = "definition_filesystem_work_bound" if stop == "work" else "definition_interrupted"
        with pytest.raises(D.DefinitionRefusedError, match=code):
            visit(discovery, caller, ALIAS + "/generic.service", LOW + "/generic.service")
        assert len(filesystem.accesses) == before
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds and state["reserved_work"] == 0
    assert all(operation == "close" for operation, _ in filesystem.accesses[before:])


@pytest.mark.parametrize("caller", ["source", "dependency"])
def test_parent_symlink_hop_bound_prevents_leaf_access_and_closes_descriptors(caller):
    filesystem = PathAwareFS()
    leaf = filesystem.add(ROOT + "/destination/generic.service", data=b"unread")
    for index in range(33):
        filesystem.add(ROOT + "/hop" + str(index), "symlink",
                       "hop" + str(index + 1) if index < 32 else "destination")
    discovery = primed(filesystem, (ROOT,))
    try:
        with pytest.raises(D.DefinitionRefusedError, match="definition_path_hops_bound"):
            visit(discovery, caller, ROOT + "/hop0/generic.service", leaf)
        assert_leaf_untouched(filesystem, leaf)
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds


def test_dependency_cycle_returns_without_an_extra_parent_walk(monkeypatch):
    filesystem = PathAwareFS()
    path = filesystem.add(ROOT + "/cycle.service", "symlink", "cycle.service")
    discovery = primed(filesystem, (ROOT,))
    original = discovery.definition_lookup_parent
    parent_calls = []

    def parent(value):
        parent_calls.append(value)
        return original(value)

    monkeypatch.setattr(discovery, "definition_lookup_parent", parent)
    try:
        assert discovery.definition_dependency_mask(path) is False
        assert parent_calls == [path]
        assert filesystem.reads == []
    finally:
        discovery.definition_close_pass()
    assert not filesystem.fds
