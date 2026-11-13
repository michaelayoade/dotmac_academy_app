# ruff: noqa: S101 -- hosted synthetic filesystem and manager qualification.
"""No real filesystem, manager, process, network, body, or host inputs."""

import copy
import errno
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import candidate_authority_discovery as D
import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_discovery_graph_schema import envelope

ROOT = "/etc/systemd/system"
LOW = "/usr/lib/systemd/system"


class Entries:
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return iter(SimpleNamespace(name=name) for name in reversed(self.names))

    def __exit__(self, *_args):
        return False


class SyntheticFS:
    """Finite POSIX subset, with anchored descriptor nodes and no real syscalls."""

    def __init__(self):
        self.nodes = {}
        self.fds = {}
        self.next_fd = 100
        self.calls = []
        self.reads = []
        self.denied = set()
        self.add("/", "directory")
        self.add("/dev/null", "device")

    def add(self, path, kind="regular", data=b"", *, uid=0, writable=False):
        path = os.path.normpath(path)
        if path != "/" and os.path.dirname(path) not in self.nodes:
            self.add(os.path.dirname(path), "directory")
        bits = {"directory": stat.S_IFDIR | 0o755, "regular": stat.S_IFREG | 0o644,
                "symlink": stat.S_IFLNK | 0o777, "device": stat.S_IFCHR | 0o666}
        self.nodes[path] = {"kind": kind, "data": data, "ino": len(self.nodes) + 1,
                            "mode": bits[kind] | (0o022 if writable else 0), "uid": uid,
                            "stamp": 1, "path": path}
        return path

    @staticmethod
    def metadata(node):
        size = len(node["data"]) if node["kind"] in ("regular", "symlink") else 4096
        return SimpleNamespace(st_dev=1, st_ino=node["ino"], st_uid=node["uid"], st_gid=0,
                               st_mode=node["mode"], st_size=size, st_mtime_ns=node["stamp"],
                               st_ctime_ns=node["stamp"], st_rdev=os.makedev(1, 3))

    def fullpath(self, path, directory=None):
        if not path.startswith("/"):
            path = os.path.join(self.fds[directory]["node"]["path"], path)
        return os.path.normpath(path)

    def syscall(self, operation, *args, **kwargs):
        self.calls.append(operation)
        if operation in ("close", "fstat", "read", "scandir"):
            fd = args[0]
            handle = self.fds[fd]
            node = handle["node"]
            path = node["path"]
            if operation == "close":
                del self.fds[fd]
                return None
            if operation == "fstat":
                return self.metadata(node)
            if operation == "scandir":
                names = [os.path.basename(p) for p in self.nodes if p != path and os.path.dirname(p) == path]
                return Entries(names)
            amount = args[1]
            chunk = node["data"][handle["offset"]:handle["offset"] + amount]
            handle["offset"] += len(chunk)
            self.reads.append((path, len(chunk)))
            return chunk
        path = self.fullpath(args[0], kwargs.get("dir_fd"))
        if path in self.denied:
            raise PermissionError(errno.EACCES, "synthetic denial")
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "synthetic absence")
        node = self.nodes[path]
        if operation == "stat":
            assert kwargs.get("follow_symlinks") is False
            return self.metadata(node)
        if operation == "readlink":
            assert node["kind"] == "symlink"
            return node["data"]
        assert operation == "open"
        if args[1] & os.O_NOFOLLOW and node["kind"] == "symlink":
            raise OSError(errno.ELOOP, "synthetic link refusal")
        if args[1] & os.O_DIRECTORY and node["kind"] != "directory":
            raise NotADirectoryError(errno.ENOTDIR, "synthetic type refusal")
        self.next_fd += 1
        self.fds[self.next_fd] = {"node": node, "offset": 0}
        return self.next_fd


class SyntheticDefinitions(D.Discovery):
    def __init__(self, filesystem, *, roots=(ROOT,), names=(), version="255.4-test", after=None, mutate=None):
        super().__init__("web")
        self.fs = filesystem
        self.roots = roots
        self.version = version
        self.after = after or {}
        self.mutate = mutate
        self.getters = []
        self.installed_units = set(names)
        self.loaded_units = set(names)
        for domain in ("systemd_installed", "systemd_loaded"):
            self.domain(domain)["enumeration_complete"] = True

    def definition_syscall(self, operation, *args, **kwargs):
        return self.fs.syscall(operation, *args, **kwargs)

    def run(self, args, domain, *, getter=False):
        assert getter and domain == D.DEFINITION_DOMAIN
        assert args[:4] == ["get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                            "org.freedesktop.systemd1.Manager"]
        field = args[-1]
        assert field in ("UnitPath", "Version")
        self.getters.append(tuple(args))
        repeated = self.definition_state()["phase"] == "repeated"
        if field == "Version":
            value = self.after.get("version", self.version) if repeated else self.version
            return ('s "' + value + '"\n').encode()
        values = self.after.get("roots", self.roots) if repeated else self.roots
        return ("as " + str(len(values)) + "".join(' "' + value + '"' for value in values) + "\n").encode()

    def definition_close_pass(self):
        super().definition_close_pass()
        if self.definition_state()["phase"] == "initial" and self.mutate is not None:
            mutation, self.mutate = self.mutate, None
            mutation(self.fs)


def observe(filesystem, **kwargs):
    discovery = SyntheticDefinitions(filesystem, **kwargs)
    discovery.template_definitions()
    return discovery


def domain(discovery):
    return discovery.domain(D.DEFINITION_DOMAIN)


def facts(discovery, name="worker@.service"):
    return next(row["facts"] for row in domain(discovery)["records"]
                if row["identity_sha256"] == D.digest(name.encode()))


def relations(discovery, name="worker@.service"):
    start, end = facts(discovery, name)["relation_range"]
    return domain(discovery)["relations"][start:end]


def base_fs(body=b"[Unit]\nRequires=base.service\n"):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/worker@.service", data=body)
    return filesystem


def test_effective_bodies_two_manager_pairs_and_hash_only_schema():
    filesystem = base_fs(b"[Unit]\nRequires=base.service\n[Service]\nExecStart=/synthetic/private-marker\n")
    discovery = observe(filesystem)
    result = facts(discovery)
    assert result["source_acquisition_complete"] and not result["activation_semantics_complete"]
    assert result["source_kind"] == "template_definition"
    assert result["classification"] == "unknown" and result["authority_refs"] == []
    assert len(discovery.getters) == 4
    assert result["definition_profile_sha256"] == "713859b6fdc5043a963a7463c0182a47ab0668416dc916019e0a88de7c6f60ab"
    assert [item["phase"] for item in domain(discovery)["source_reads"]] == ["initial", "repeated"]
    assert len(filesystem.reads) == 2 and all(path.endswith("worker@.service") for path, _size in filesystem.reads)
    assert not filesystem.fds
    encoded = json.dumps(envelope(discovery))
    assert "private-marker" not in encoded and "worker@.service" not in encoded and "base.service" not in encoded
    schema = json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(envelope(discovery))


@pytest.mark.parametrize("changes", [{"version": "256.1"}, {"roots": (ROOT, "/outside/profile")}])
def test_unsupported_manager_state_never_accesses_filesystem(changes):
    filesystem = base_fs()
    discovery = observe(filesystem, **changes)
    assert filesystem.calls == [] and domain(discovery)["complete"] == 0
    assert not domain(discovery)["enumeration_complete"]
    assert len(discovery.getters) == 4


@pytest.mark.parametrize("after", [{"version": "255.5-test"}, {"roots": (LOW, ROOT)}])
def test_manager_version_and_order_changes_refuse_success(after):
    filesystem = base_fs()
    filesystem.add(LOW, "directory")
    discovery = observe(filesystem, roots=(ROOT, LOW), after=after)
    assert "definition_manager_changed" in domain(discovery)["gaps"]
    assert not facts(discovery)["source_acquisition_complete"]


def test_absence_is_bracketed_and_denial_is_not_absence():
    filesystem = SyntheticFS()
    filesystem.add("/etc/systemd", "directory")
    missing = observe(filesystem, names=("worker@.service",))
    assert any(item["kind"] == "absent" for item in domain(missing)["path_observations"])
    assert "definition_fragment_absent" in facts(missing)["unresolved_requirements"]
    filesystem = base_fs()
    filesystem.denied.add(ROOT)
    denied = observe(filesystem)
    assert "definition_access_denied" in domain(denied)["gaps"]
    assert not any(item["kind"] == "absent" for item in domain(denied)["path_observations"])


def test_alias_lower_path_destination_is_resolved_again_through_precedence_and_reverse_aliases():
    filesystem = base_fs()
    filesystem.add(LOW + "/worker@.service", data=b"[Unit]\nRequires=shadowed.service\n")
    filesystem.add(ROOT + "/alias@.service", "symlink", LOW + "/worker@.service")
    discovery = observe(filesystem, roots=(ROOT, LOW))
    result = facts(discovery, "alias@.service")
    assert result["source_acquisition_complete"]
    assert result["canonical_identity_sha256"] == D.digest(b"worker@.service")
    assert result["aliases"]["identity_sha256"] == [D.digest(b"alias@.service")]
    assert D.digest(b"base.service") in [row["value_sha256"] for row in relations(discovery, "alias@.service")]
    assert all(path != LOW + "/worker@.service" for path, _size in filesystem.reads)


def test_compile_approved_root_does_not_approve_linked_body_outside_actual_unitpath():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/worker@.service", "symlink", LOW + "/different-name.service")
    filesystem.add(LOW + "/different-name.service", data=b"[Unit]\nRequires=never-read.service\n")
    discovery = observe(filesystem)
    result = facts(discovery)
    assert result["fragment_kind"] == "linked_unit" and not result["source_acquisition_complete"]
    assert result["linked_target_sha256"] == D.digest((LOW + "/different-name.service").encode())
    assert "definition_linked_unit_unprofiled" in result["unresolved_requirements"]
    assert filesystem.reads == [] and result["sources"] == []


@pytest.mark.parametrize("mask", ["empty", "null"])
def test_verified_masks_are_source_facts_without_sender_authority(mask):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/worker@.service", "regular" if mask == "empty" else "symlink",
                   b"" if mask == "empty" else "/dev/null")
    discovery = observe(filesystem)
    result = facts(discovery)
    assert result["mask"] and result["source_acquisition_complete"]
    assert result["classification"] == "unknown" and not result["activation_semantics_complete"]
    assert all(path != "/dev/null" for path, _size in filesystem.reads)
    assert domain(discovery)["definition_accounting"]["body_bytes"] == 0


@pytest.mark.parametrize("kind", ["cycle", "dangling"])
def test_alias_cycles_and_dangling_aliases_remain_incomplete(kind):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/worker@.service", "symlink", "other@.service")
    if kind == "cycle":
        filesystem.add(ROOT + "/other@.service", "symlink", "worker@.service")
    discovery = observe(filesystem)
    assert not facts(discovery)["source_acquisition_complete"]
    assert "definition_alias_" + kind in facts(discovery)["unresolved_requirements"]


def test_incompatible_alias_is_ignored_like_v255_before_lower_mapping():
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/worker@.service", "symlink", LOW + "/other@.timer")
    filesystem.add(LOW + "/worker@.service", data=b"[Unit]\nRequires=lower.service\n")
    discovery = observe(filesystem, roots=(ROOT, LOW))
    assert facts(discovery)["source_acquisition_complete"]
    assert any(row["kind"] == "ignored_incompatible_alias" for row in domain(discovery)["path_observations"])
    assert [row["value_sha256"] for row in relations(discovery)] == [D.digest(b"lower.service")]


@pytest.mark.parametrize("name,expected", [
    ("foo-bar@.service", ["foo-bar@.service", "foo-.service"]),
    ("foo-bar@one.service", ["foo-bar@one.service", "foo-bar@.service", "foo-.service",
                             "foo-@one.service", "foo-@.service"]),
])
def test_exact_v255_abstract_and_actual_instance_prefix_recursion_order(name, expected):
    assert D.Discovery.definition_candidate_dirs(name) == expected


@pytest.mark.parametrize("name", ["foo-bar@.service", "foo-bar@one.service"])
def test_plain_prefix_wins_before_template_and_instance_prefix_competitors(name):
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/foo-bar@.service", data=b"[Unit]\nRequires=base.service\n")
    filesystem.add(ROOT + "/foo-.service.d/30.conf", data=b"[Unit]\nRequires=plain-prefix.service\n")
    filesystem.add(ROOT + "/foo-@.service.d/30.conf", data=b"[Unit]\nRequires=wrong-template-prefix.service\n")
    filesystem.add(ROOT + "/foo-@one.service.d/30.conf", data=b"[Unit]\nRequires=instance-prefix.service\n")
    discovery = observe(filesystem, names=(name,))
    assert facts(discovery, name)["source_acquisition_complete"]
    values = [row["value_sha256"] for row in relations(discovery, name)]
    assert values == [D.digest(b"base.service"), D.digest(b"plain-prefix.service")]
    assert not any("foo-@" in path for path, _size in filesystem.reads)


def test_root_precedence_precedes_specificity_and_winners_are_basename_lexical():
    filesystem = base_fs()
    filesystem.add(LOW + "/worker@.service.d/20.conf", data=b"[Unit]\nRequires=wrong.service\n")
    filesystem.add(ROOT + "/worker@.service.d/20.conf", data=b"[Unit]\nRequires=twenty.service\n")
    filesystem.add(LOW + "/worker@.service.d/10.conf", data=b"[Unit]\nRequires=ten.service\nRequires=\n")
    filesystem.add(ROOT + "/service.d/20.conf", data=b"[Unit]\nRequires=type-shadowed.service\n")
    discovery = observe(filesystem, roots=(ROOT, LOW))
    assert facts(discovery)["source_acquisition_complete"]
    assert [row["value_sha256"] for row in relations(discovery)] == [
        D.digest(b"base.service"), D.digest(b"ten.service"), D.digest(b"twenty.service"),
    ]
    assert all("service.d/20.conf" not in path or "worker@.service.d" in path for path, _size in filesystem.reads)


def test_competing_reverse_alias_basename_is_explicitly_unresolved_and_unread():
    filesystem = base_fs()
    for alias in ("left", "right"):
        filesystem.add(ROOT + "/" + alias + "@.service", "symlink", "worker@.service")
        filesystem.add(ROOT + "/" + alias + "@.service.d/10.conf", data=b"[Unit]\nWants=other.service\n")
    discovery = observe(filesystem)
    assert not facts(discovery)["source_acquisition_complete"]
    assert "definition_alias_order_ambiguous" in facts(discovery)["unresolved_requirements"]
    assert not any(path.endswith(".conf") for path, _size in filesystem.reads)


def test_dependency_directory_masks_dangling_and_mismatch_follow_entry_basename():
    filesystem = base_fs()
    filesystem.add(ROOT + "/worker@.service.wants/masked.service", "symlink", "/dev/null")
    filesystem.add(ROOT + "/worker@.service.wants/dangling.service", "symlink", "../not-present.service")
    filesystem.add(ROOT + "/actual.service", data=b"[Unit]\n")
    filesystem.add(ROOT + "/worker@.service.requires/entry.service", "symlink", "../actual.service")
    filesystem.add(ROOT + "/worker@.service.upholds/upheld.service", "symlink", "../actual.service")
    discovery = observe(filesystem)
    pairs = [(row["directive"], row["value_sha256"]) for row in relations(discovery)]
    assert ("Wants", D.digest(b"masked.service")) not in pairs
    assert ("Wants", D.digest(b"dangling.service")) in pairs
    assert ("Requires", D.digest(b"entry.service")) in pairs
    assert ("Upholds", D.digest(b"upheld.service")) in pairs
    assert any(row.get("compatibility") == "mismatched_warning" for row in domain(discovery)["path_observations"])
    assert facts(discovery)["source_acquisition_complete"]


def test_additive_empty_assignments_continuations_and_native_escapes():
    body = (b"[Unit]\nRequires=first.service \\\n# skipped comment\n second.service\nRequires=\n"
            b"Requires=first.service native\\x2dname.service\nBefore=ordered.service\n"
            b"PropagatesStopTo=stopped.service\n")
    discovery = observe(base_fs(body))
    rows = relations(discovery)
    assert [row["value_sha256"] for row in rows if row["directive"] == "Requires"] == [
        D.digest(value) for value in (b"first.service", b"second.service", b"first.service", rb"native\x2dname.service")
    ]
    assert {row["directive"] for row in rows} >= {"Requires", "Before", "PropagatesStopTo"}


@pytest.mark.parametrize("owner,word,kind,target", [
    ("worker@.service", "other@.service", "symbolic", "other@.service"),
    ("worker@one.service", "other@.service", "dependency", "other@one.service"),
    ("plain.service", "other@.service", "dependency", "other@plain.service"),
    ("worker@.service", "%p-%j.service", "dependency", "worker-worker.service"),
    ("worker@.service", "%i.service", "symbolic", "%i.service"),
    ("worker@.service", "%n", "symbolic", "%n"),
    ("worker@.service", "%N.service", "symbolic", "%N.service"),
    ("worker@one.service", "%i.service", "dependency", "one.service"),
    ("worker@one.service", "%n", "dependency", "worker@one.service"),
])
def test_literal_and_symbolic_specifiers_never_invent_loaded_instances(owner, word, kind, target):
    discovery = SyntheticDefinitions(SyntheticFS())
    discovery.reduce_definition_relations(owner, [{"kind": "dependency", "directive": "Requires",
                                                 "source": 0, "value": word}])
    row = domain(discovery)["relations"][0]
    assert row["kind"] == kind and row["value_sha256"] == D.digest(target.encode())
    assert discovery.fs.calls == [] and discovery.getters == []
    if kind == "symbolic":
        assert row["symbolic_type"] in ("implicit_instance", "specifier")


@pytest.mark.parametrize("word", ['"quoted.service"', "bad/name.service", "%X.service",
                                 "literal%%.service", "%%i-%i.service"])
def test_unsupported_dependency_grammar_is_a_hashed_unresolved_requirement(word):
    discovery = observe(base_fs(("[Unit]\nRequires=" + word + "\n").encode()))
    assert relations(discovery)[0]["kind"] == "unresolved"
    assert facts(discovery)["source_acquisition_complete"]
    assert not facts(discovery)["activation_semantics_complete"]


def test_specifier_expansion_is_bounded_before_allocating_a_large_unit_name():
    expanded, symbolic, failure = D.Discovery.definition_expand_specifiers(
        "a" * 200 + "@.service", "%p" * 10000 + ".service"
    )
    assert expanded is None and symbolic == "" and failure == "dependency_name_unsupported"


@pytest.mark.parametrize("section,directive", [("Timer", "Unit"), ("Path", "Unit"),
                                                ("Socket", "Service"), ("Socket", "Accept")])
def test_activation_directives_are_projections_until_reducers_exist(section, directive):
    name = "worker@." + section.lower()
    filesystem = SyntheticFS()
    filesystem.add(ROOT + "/" + name, data=("[" + section + "]\n" + directive + "=synthetic-value\n").encode())
    discovery = observe(filesystem)
    assert relations(discovery, name)[0]["directive"] == section + "." + directive
    assert relations(discovery, name)[0]["kind"] == "projection"
    assert not facts(discovery, name)["activation_semantics_complete"]


def test_sections_for_other_unit_types_do_not_create_positive_dependencies():
    discovery = observe(base_fs(b"[Timer]\nUnit=ignored.service\n[Unknown]\nRequires=ignored.service\n"
                               b"[Unit]\nRequires=actual.service\n"))
    assert [row["value_sha256"] for row in relations(discovery)] == [D.digest(b"actual.service")]


def test_stable_metadata_and_size_cannot_hide_changed_body():
    filesystem = base_fs(b"[Unit]\nRequires=left.service\n")
    discovery = observe(filesystem, mutate=lambda fs: fs.nodes[ROOT + "/worker@.service"].update(
        data=b"[Unit]\nRequires=rite.service\n"
    ))
    assert "definition_snapshot_changed" in domain(discovery)["gaps"]
    assert not facts(discovery)["source_acquisition_complete"]
    bodies = domain(discovery)["source_reads"]
    assert len(bodies) == 2 and bodies[0]["bytes"] == bodies[1]["bytes"]
    assert bodies[0]["body_sha256"] != bodies[1]["body_sha256"]


@pytest.mark.parametrize("race", ["alias", "directory"])
def test_alias_and_consulted_directory_races_refuse_source_completeness(race):
    filesystem = base_fs()
    if race == "alias":
        filesystem.add(ROOT + "/alias@.service", "symlink", "worker@.service")
        def mutation(fs):
            fs.nodes[ROOT + "/alias@.service"].update(data="missing@.service")
    else:
        filesystem.add(ROOT + "/worker@.service.d", "directory")
        def mutation(fs):
            fs.add(ROOT + "/worker@.service.d/10.conf", data=b"[Unit]\nWants=new.service\n")
    discovery = observe(filesystem, mutate=mutation)
    assert not facts(discovery)["source_acquisition_complete"]
    assert any(code in domain(discovery)["gaps"] for code in (
        "definition_snapshot_changed", "definition_selected_sources_changed",
    ))


def test_credential_environment_and_execution_references_are_never_dereferenced():
    filesystem = base_fs(b"[Service]\nEnvironmentFile=/outside/private\nLoadCredential=key:/outside/key\n"
                         b"ExecStart=/outside/executable private-value\n")
    filesystem.add("/outside/private", data=b"never-read-this")
    discovery = observe(filesystem)
    assert all(path == ROOT + "/worker@.service" for path, _size in filesystem.reads)
    encoded = json.dumps(domain(discovery))
    assert "private-value" not in encoded and "never-read-this" not in encoded
    assert facts(discovery)["source_acquisition_complete"]
    opaque = [row for row in relations(discovery) if row["kind"] == "unsupported"]
    assert len(opaque) == 2 and all(row["directive"] == "Unsupported" for row in opaque)
    assert "directive_semantics_unresolved" in facts(discovery)["unresolved_requirements"]
    assert any(row["directive"] == "ExecStart" and row["kind"] == "projection" for row in relations(discovery))


def test_permitted_root_component_link_is_anchored_and_unknown_destination_is_not_accessed():
    filesystem = SyntheticFS()
    filesystem.add(LOW + "/worker@.service", data=b"[Unit]\nRequires=base.service\n")
    filesystem.add("/lib", "symlink", "usr/lib")
    discovery = observe(filesystem, roots=("/lib/systemd/system",))
    assert facts(discovery)["source_acquisition_complete"]
    assert any(row["kind"] == "component_symlink" for row in domain(discovery)["path_observations"])
    assert all(path == LOW + "/worker@.service" for path, _size in filesystem.reads)
    filesystem = SyntheticFS()
    filesystem.add(ROOT, "symlink", "/outside/unapproved")
    filesystem.denied.add("/outside")
    discovery = observe(filesystem)
    assert "definition_link_outside_profile" in domain(discovery)["gaps"]
    assert "definition_access_denied" not in domain(discovery)["gaps"]
    assert filesystem.reads == []


@pytest.mark.parametrize("size", [262144, 262145])
def test_body_read_cap_is_enforced_before_opening_an_oversized_body(size):
    filesystem = base_fs(b"#" + b"x" * (size - 1))
    discovery = observe(filesystem)
    if size == 262144:
        assert facts(discovery)["source_acquisition_complete"]
        assert domain(discovery)["definition_accounting"]["body_bytes"] == 2 * size
    else:
        assert "definition_body_read_bound" in domain(discovery)["gaps"]
        assert filesystem.reads == []


@pytest.mark.parametrize("counter,value,code", [
    ("work", 12000, "definition_filesystem_work_bound"),
    ("files", 16384, "definition_shared_file_bound"),
    ("deadline", 0, "definition_interrupted"),
])
def test_work_shared_allowance_and_deadline_fail_before_io(counter, value, code):
    discovery = SyntheticDefinitions(SyntheticFS())
    state = discovery.definition_state()
    if counter == "work":
        state["work"] = value
    else:
        setattr(discovery, counter, value)
    with pytest.raises(D.DefinitionRefusedError, match=code):
        discovery.definition_io("stat", "/", follow_symlinks=False)
    assert discovery.fs.calls == [] and state["unparsed_tail"]


@pytest.mark.parametrize("bound", ["work", "shared", "deadline"])
def test_directory_iterator_is_never_advanced_at_zero_allowance(monkeypatch, bound):
    discovery = SyntheticDefinitions(base_fs())
    filesystem = discovery.fs
    original = filesystem.syscall
    fetched = []

    class Spy:
        def __enter__(self):
            state = discovery.definition_state()
            if bound == "work":
                state["work"] = 12000 - state["reserved_work"]
            elif bound == "shared":
                discovery.files = 16384 - state["reserved_work"]
            else:
                discovery.deadline = 0
            return self

        def __next__(self):
            fetched.append(True)
            return SimpleNamespace(name="worker@.service")

        def __exit__(self, *_args):
            return False

    def syscall(operation, *args, **kwargs):
        return Spy() if operation == "scandir" else original(operation, *args, **kwargs)

    monkeypatch.setattr(filesystem, "syscall", syscall)
    with pytest.raises(D.DefinitionRefusedError):
        discovery.definition_scan(ROOT)
    discovery.definition_close_pass()
    assert fetched == [] and not filesystem.fds


def test_second_pass_reserves_bytes_and_work_before_first_body_admission():
    discovery = SyntheticDefinitions(base_fs())
    state = discovery.definition_state()
    state["active_roots"] = (ROOT,)
    state["work"] = 11900
    path = ROOT + "/worker@.service"
    identity = D.Discovery.file_identity(discovery.fs.metadata(discovery.fs.nodes[path]))
    with pytest.raises(D.DefinitionRefusedError, match="definition_second_pass_reservation_bound"):
        discovery.read_definition_source({"path": path, "metadata": {"identity": identity}})
    discovery.definition_close_pass()
    assert not discovery.fs.reads
    discovery = SyntheticDefinitions(base_fs())
    discovery.definition_state()["body_bytes"] = 33554432
    discovery.template_definitions()
    assert "definition_body_total_bound" in domain(discovery)["gaps"] and not discovery.fs.reads


def test_second_read_can_use_its_reserved_work_after_unreserved_work_is_exhausted():
    discovery = SyntheticDefinitions(base_fs())
    state = discovery.definition_state()
    state["active_roots"] = (ROOT,)
    path = ROOT + "/worker@.service"
    identity = D.Discovery.file_identity(discovery.fs.metadata(discovery.fs.nodes[path]))
    selected = {"path": path, "metadata": {"identity": identity}}
    discovery.read_definition_source(selected)
    discovery.definition_close_pass()
    assert state["reserved_work"] > 0 and state["reserved_bytes"] > 0
    state["work"] = 12000 - state["reserved_work"]
    state["phase"] = "repeated"
    discovery.read_definition_source(selected)
    discovery.definition_close_pass()
    assert state["reserved_work"] == state["reserved_bytes"] == 0
    assert state["work"] <= 12000 and len(domain(discovery)["source_reads"]) == 2


def test_total_body_bytes_accepts_exact_reserved_boundary_and_refuses_next_body():
    discovery = SyntheticDefinitions(base_fs())
    state = discovery.definition_state()
    state["active_roots"] = (ROOT,)
    path = ROOT + "/worker@.service"
    metadata = discovery.fs.metadata(discovery.fs.nodes[path])
    selected = {"path": path, "metadata": {"identity": D.Discovery.file_identity(metadata)}}
    state["body_bytes"] = 33554432 - 2 * metadata.st_size
    discovery.read_definition_source(selected)
    discovery.definition_close_pass()
    state["phase"] = "repeated"
    discovery.read_definition_source(selected)
    discovery.definition_close_pass()
    assert state["body_bytes"] == 33554432 and state["reserved_bytes"] == 0
    state["phase"] = "initial"
    extra = discovery.fs.add(ROOT + "/extra@.service", data=b"x")
    identity = D.Discovery.file_identity(discovery.fs.metadata(discovery.fs.nodes[extra]))
    with pytest.raises(D.DefinitionRefusedError, match="definition_body_total_bound"):
        discovery.read_definition_source({"path": extra, "metadata": {"identity": identity}})
    discovery.definition_close_pass()
    assert len(discovery.fs.reads) == 2


def test_target_overflow_never_produces_a_successful_prefix():
    filesystem = SyntheticFS()
    for number in range(129):
        filesystem.add(ROOT + "/worker" + str(number) + "@.service", data=b"[Unit]\n")
    discovery = observe(filesystem)
    assert domain(discovery)["enumerated"] == domain(discovery)["skipped"] == 129
    assert domain(discovery)["records"] == [] and filesystem.reads == []
    assert "definition_target_bound" in domain(discovery)["gaps"]


def test_distinct_map_name_and_selected_path_caps_are_independent():
    discovery = SyntheticDefinitions(SyntheticFS())
    metadata = {"identity": (1, 1, 0, 0, stat.S_IFREG | 0o644, 1, 1, 1),
                "target": None, "mode": stat.S_IFREG | 0o644, "size": 1, "uid": 0}
    entries = {"worker" + str(number) + "@.service": metadata for number in range(8193)}
    with pytest.raises(D.DefinitionRefusedError, match="definition_map_names_bound"):
        discovery.build_unit_name_map([{"path": ROOT, "resolved": ROOT, "entries": entries}])
    discovery = SyntheticDefinitions(SyntheticFS())
    discovery.definition_state()["selected_paths"] = {"synthetic-" + str(number) for number in range(512)}
    with pytest.raises(D.DefinitionRefusedError, match="definition_selected_total_bound"):
        discovery.read_definition_source({"path": ROOT + "/extra@.service"})
    assert discovery.fs.calls == []


def test_per_definition_selected_source_limit_refuses_before_any_body_read():
    filesystem = base_fs()
    for number in range(64):
        filesystem.add(ROOT + "/worker@.service.d/" + str(number) + ".conf", data=b"[Unit]\n")
    discovery = observe(filesystem)
    assert "definition_selected_per_target_bound" in domain(discovery)["gaps"]
    assert filesystem.reads == []


def test_alias_lookup_and_path_link_hops_have_distinct_limits():
    discovery = SyntheticDefinitions(SyntheticFS())
    metadata = {"identity": (1, 1, 0, 0, stat.S_IFREG | 0o644, 1, 1, 1),
                "target": None, "mode": stat.S_IFREG | 0o644, "size": 1, "uid": 0}
    mapping = {}
    for number in range(8):
        name = "worker" + str(number) + "@.service"
        mapping[name] = {"kind": "alias", "destination": "worker" + str(number + 1) + "@.service",
                         "path": ROOT + "/" + name, "metadata": metadata}
    mapping["worker8@.service"] = {"kind": "regular", "destination": None,
                                   "path": ROOT + "/worker8@.service", "metadata": metadata}
    assert discovery.resolve_template_fragment("worker0@.service", mapping)["failure"] == "definition_alias_hops_bound"
    filesystem = SyntheticFS()
    filesystem.add(ROOT, "directory")
    for number in range(33):
        filesystem.add(ROOT + "/link" + str(number), "symlink", "link" + str(number + 1))
    filesystem.add(ROOT + "/link33", "directory")
    discovery = SyntheticDefinitions(filesystem)
    with pytest.raises(D.DefinitionRefusedError, match="definition_path_hops_bound"):
        discovery.definition_directory(ROOT + "/link0")
    discovery.definition_close_pass()


def test_path_bytes_and_manager_command_limits_refuse_before_extra_operation():
    discovery = SyntheticDefinitions(SyntheticFS())
    oversized = SimpleNamespace(st_size=4097)
    with pytest.raises(D.DefinitionRefusedError, match="definition_path_bytes_bound"):
        discovery.definition_link(100, "synthetic", oversized)
    assert discovery.fs.calls == []
    discovery.manager_unitpath_snapshot("initial")
    discovery.manager_unitpath_snapshot("repeated")
    with pytest.raises(D.DefinitionRefusedError, match="definition_manager_command_bound"):
        discovery.manager_unitpath_snapshot("repeated")
    assert len(discovery.getters) == 4


def test_relation_attempts_include_duplicates_and_malformed_and_refuse_overflow():
    discovery = SyntheticDefinitions(SyntheticFS())
    words = " ".join(["same.service"] * 1024 + ["bad/name"])
    with pytest.raises(D.DefinitionRefusedError, match="definition_relation_target_bound"):
        discovery.reduce_definition_relations("worker@.service", [
            {"kind": "dependency", "directive": "Requires", "source": 0, "value": words},
        ])
    assert discovery.definition_state()["relation_attempts"] == len(domain(discovery)["relations"]) == 1024
    discovery = SyntheticDefinitions(SyntheticFS())
    result = discovery.reduce_definition_relations("worker@.service", [
        {"kind": "dependency", "directive": "Requires", "source": 0, "value": "same.service bad/name same.service"},
    ])
    assert result["attempts"] == 3 and domain(discovery)["relations"][1]["kind"] == "unresolved"
    discovery.definition_state()["relation_attempts"] = 32768
    with pytest.raises(D.DefinitionRefusedError, match="definition_relation_total_bound"):
        discovery.reduce_definition_relations("worker@.service", [
            {"kind": "dependency", "directive": "Requires", "source": 0, "value": "one.service"},
        ])


@pytest.mark.parametrize("table,cap,size", [("path_observations", 4096, 768),
                                           ("source_reads", 1024, 1024), ("relations", 32768, 256)])
def test_table_and_record_bounds_never_append_a_truncated_record(table, cap, size):
    discovery = SyntheticDefinitions(SyntheticFS())
    discovery.definition_state()
    with pytest.raises(D.DefinitionRefusedError, match="record_bound"):
        discovery.definition_append(table, {"synthetic": "x" * size}, cap, size)
    assert domain(discovery)[table] == []
    domain(discovery)[table] = [None] * cap
    with pytest.raises(D.DefinitionRefusedError, match="definition_" + table + "_bound"):
        discovery.definition_append(table, {}, cap, size)
    assert len(domain(discovery)[table]) == cap


def test_evidence_and_definition_header_caps_are_pre_admission():
    discovery = SyntheticDefinitions(SyntheticFS())
    discovery.definition_state()["encoded_bytes"] = 15728640
    with pytest.raises(D.DefinitionRefusedError, match="definition_evidence_bound"):
        discovery.definition_append("relations", {}, 32768, 256)
    assert domain(discovery)["relations"] == []
    discovery = SyntheticDefinitions(SyntheticFS())
    with pytest.raises(D.DefinitionRefusedError, match="definition_header_bound"):
        discovery.definition_commit("worker@.service", {"synthetic": "x" * 8192})
    assert domain(discovery)["records"] == []
    discovery.deadline = 0
    with pytest.raises(D.DefinitionRefusedError, match="definition_interrupted"):
        discovery.definition_append("relations", {}, 32768, 256)
    assert domain(discovery)["relations"] == []


@pytest.mark.parametrize("raw,signature", [
    (b'as 2 "/etc/systemd/system"\n', "as"),
    (b'as 01 "/etc/systemd/system"\n', "as"),
    (b'as 1 "/etc/systemd/\\x73ystem"\n', "as"),
    (b's "255" trailing\n', "s"),
    (b's "255\\n"\n', "s"),
    (b's "' + b"x" * 131072 + b'"\n', "s"),
])
def test_manager_typed_grammar_refuses_count_escape_trailing_and_byte_overflow(raw, signature):
    assert D.Discovery.definition_typed_strings(raw, signature) is None


def test_profile_and_closed_schema_reject_upgrades_and_plaintext():
    discovery = observe(base_fs())
    schema = json.loads((Path(__file__).parents[1] / "discovery.schema.json").read_text())
    validator = Draft202012Validator(schema)
    report = envelope(discovery)
    validator.validate(report)
    for scope, key, value in (("facts", "activation_semantics_complete", True),
                              ("facts", "classification", "non_sender"),
                              ("facts", "authority_refs", ["forged"]),
                              ("facts", "raw_body", "private-value"),
                              ("facts", "source_kind", "runtime_properties"),
                              ("profile", "alias_hops", 32),
                              ("profile", "allowed_roots", ["/outside/profile"])):
        malformed = copy.deepcopy(report)
        item = malformed["domains"][D.DEFINITION_DOMAIN]["records"][0]["facts"]
        target = item if scope == "facts" else item["definition_profile"]
        target[key] = value
        with pytest.raises(ValidationError):
            validator.validate(malformed)

