"""Private unqualified history evidence; never whole-product adoption authority.

The coordinator fences/drains ALL writers before obtaining the complete ordered
lockset. This module checks those locks, never treats a caller flag as a fence.
Token conservation delegates full-row checks to its private established owner.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field, replace
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, cast
from weakref import ReferenceType, WeakKeyDictionary, ref

import dotmac_learning as learning
import sqlalchemy as sa
from dotmac_kernel.migrations import versions_dir as kernel_versions
from dotmac_learning.migrations import versions_dir as learning_versions
from sqlalchemy.engine import Connection

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import account_token_identity as tokens
from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import lab_claim_lease_transition as lab_claim
from app.maintenance import learning_history as history
from app.maintenance import retained_environment as environment
from app.maintenance import retained_history as retained
from app.maintenance import retained_hosted_genesis as hosted
from app.maintenance import retained_transition as transition
from app.maintenance.identity_history import _connection_preflight
from app.migration_graph import ordinary_migration_config

if TYPE_CHECKING:
    from app.maintenance.identity_history import AcademyIdentityHistoryDecoder


class ProductAdoptionRefused(RuntimeError):
    """Material-free refusal; the coordinator must roll back its entire root."""


def _require(condition):
    if not condition:
        raise ProductAdoptionRefused("Academy product evidence refused; root rollback required")


# Genuine frozen096 manifest, independently matched to all62 actual a5 blobs.
# Source inspection alone is never installed-artifact qualification.
# These are immutable schema/source contracts, never business configuration.
_FROZEN62 = (
    ("0005_labs.py", 3933, "1febeebbae42ab1aa66f6e0a3648fc5b84b53d53644ef7e19a7779b0bb2e8404"),
    ("0006_platform_settings.py", 1136, "638f6cbf8e210aee9e56f95740fec16c32d5bea4d5280beac8ca32c7f73d10d9"),
    ("0007_person_profile.py", 984, "5ba2d46aa152ce4531289fcdfe500a1de5195d606fab6d480bb258e1efd2b40a"),
    ("0008_course_offerings.py", 3270, "e818b9f05c60067b25999a9a3494aa4d7d26ea3a8cebcc598c0851aaaeedd548"),
    ("0009_offering_window.py", 770, "4376d5c7b121e84ef671829a0293de3e95d6ea6772dbbdb9f7303bf39f632772"),
    ("0010_course_completions.py", 2420, "71a5685aaee0de29b84b10c4b915cae9a28b81d896b2514c6d53232b9c5d497b"),
    ("0011_certificates.py", 2268, "971d76b1e8ba215153639992f0e4f065ef39205bfeae84137786d631d256921f"),
    ("0012_offering_activities.py", 2561, "b3980420b3b5bdbedf497f4725f3081c551decf3437ea224e52031fab90610d0"),
    ("0013_course_prerequisites.py", 2430, "76150f830515a1e75f3e355364fd9f5c49e33d08218b0be14a349d775c611af8"),
    ("0014_account_tokens.py", 2267, "bbe1d5ab93f59424b8183b997ad1541eaaeb161f776f1ca8b6ec2e4559536996"),
    ("0015_person_status.py", 502, "f3157118ce9e4dfbe85fa6141f9dc3d9e900552a90d81af168e11ee48d6479c8"),
    ("0016_activity_max_attempts.py", 464, "7c26ff37a40b81f662a49c6788bfbdf1889e4cd2b8de7f86eff57e457c44f2bd"),
    ("0017_activity_grading.py", 504, "7623567feb5649b0655977ff9bcab51f5386f453839989110a1d079d928aca03"),
    ("0018_course_status.py", 556, "c0e34afcfd3498b9a54db72386d6ca0d08fc91266218bc0612c64291452dc911"),
    ("0019_chapter_body_md.py", 467, "269908422fbe6e9c520ec3f3593b911065dc0912a4c831266d4a189bc1a0d152"),
    ("0020_activity_attempts.py", 2498, "81adde48bcd94469ecb02300d714c11b778a51cf4fdb3988b4336ced9824325f"),
    ("0020_notifications.py", 2287, "f3bf479ae08977b1b38286fa5b0b143dd394d13f298c39494a031a5a25c40f33"),
    ("0021_announcements.py", 2475, "0b77f7ebb01d2eba8fb10ad25c94a40d280b6b07ad210594cba49fe697528c7e"),
    ("0022_activity_weight.py", 423, "9abfce03c6dbbc9ba2f0206a560ba864be0bfc8da1c6e04259a737fcdc9c47dc"),
    ("0023_merge_gaps_attempts_heads.py", 597, "47e10f287a34d7e2af369deaf8863f3468ac8e8875c19e03faad7eefa470932b"),
    ("0024_chapter_reads.py", 1970, "0d187a865509021e2152e1c06ff5ef6e9a47e4c1400874718870de542d9a7bee"),
    ("0025_admissions.py", 2988, "e8e5ab8015b353f67b6d4e9324cfb054d4c6498f8b58ef8f1c633e2da55c63a7"),
    ("0026_class_sessions.py", 3201, "5a41c425aa7c3064432d43db5ce1bea9fc39874816af60fcc01715e18357e82b"),
    ("0027_assessment_mode.py", 721, "7981defee43ef9398d36d64e02f69b675aa3657e73a2b7d5ae22e61d31082726"),
    ("0028_onboarding_tasks.py", 2812, "8f07415391080426dd6f645cbcb9d1a7f3dc89d683f7cd432257860017823a78"),
    ("0029_completion_erp_synced.py", 517, "b81a71ef6378ae84a7135f4c0d21f532230b3546d3dc9f3b5b9df2a16bb9c436"),
    ("0030_entrance_assessment.py", 1715, "a4eb78a5115b18711506cb6db722c31e9c60b0875dd776e76e5ed7c367c1b580"),
    ("0031_applicant_assessment_token.py", 502, "300e85d6eee504a76afd4aa1a321b4fb732766c69a7c4219b0a2c6627e60d38c"),
    ("0032_entrance_timer.py", 887, "54e3794198ff270344a858d8a0a012038e841768765f9ce8105a85a5981e879b"),
    ("0033_tenant_default_entrance.py", 733, "e00d7d823b9c4843b1b3e7e3ec6174b1785e88bcd3ae4b0f6ef63a9bd97c875e"),
    ("0036_tracks.py", 7418, "1c8297a03559f09f8ddda42b21255587276a36f933f13d0bff2913ced053be2a"),
    ("0037_pause_entrance_timer.py", 585, "f44ee8eb3b5e1fa408acc21a120a3c71d6b24391b136f9019cf4f52b59973bec"),
    ("0038_onboarding_token.py", 497, "def53e06c77a7e64d06a0b2d9d7dfde9a802104edab3142b6482f2de586a9424"),
    ("0039_auto_accept_threshold.py", 487, "3729acc0356709216c2f92983ea350a45b356b13970a172eef308dce430446da"),
    ("0040_merge_tracks_admissions.py", 561, "bf2090ebe86706087c17a3a2bdc903c284b97545aa751fcbbe8d6b63e9eb9182"),
    ("0041_review_remediation.py", 7663, "04f1566ea2ab508eea96207652917a3b6ce5d278f7cefc4f99f94224a0b93060"),
    ("0042_course_listed.py", 1196, "3def18d99d255ab0cd13adb66c5eb6023e1ae061ad0fedc47c74ed46199eb68e"),
    ("0043_bookmarks_notes.py", 2324, "07515bb75f3d652b0b3029c560b2edcfc5fc72c3ce42bb825cc74084db3cc546"),
    ("0044_reminders.py", 3898, "04d7532c390e95c4d88d0ebf69fe92d681450b643d94d131e4f55768bf3153e3"),
    ("0045_learning_events.py", 2761, "870e0345e74481a4451d487afdcf7e40abc2b10ba3e114a68089448b3ef5d570"),
    ("0046_success_queue.py", 3611, "25d94ccc54d14ff95861345d0b15a20e6823b03b1899b40d2a57d14490809199"),
    ("0047_learning_event_dedup.py", 1208, "4f06d99be151b6a97d47951e85e06176c6dc4ab54df4c69c8e9aece8a2751dd8"),
    ("0048_subtopic_reads.py", 2181, "218a2e066370724baca846429f3ce89d7723f9d0cba9e0b3883bac25ce5721d5"),
    ("0049_enrollment_audience.py", 1856, "211b36f1b8055304c2aa84f2c3c37856011a0447211754ca3eb555c5d30456f7"),
    ("0050_enrollment_access_extension.py", 729, "589c23d4078e5ee08476614987eb2a82fa1b23ef66954712ad07b723388ca577"),
    ("0051_attempt_grants.py", 2952, "bb787257721d4521d71b8823e2ffcdf142035c6269a2550f0e8e9865c8482338"),
    ("0052_erp_applicant_assessments.py", 2627, "e7c67dbcc7ff2dc6eb59d2334f3a3c73eda89478bc7733cdb1bcfa46a1da1d9a"),
    ("0053_entrance_defaults_table.py", 3923, "d9a77e4084e5fbf68d74b61b278738396b3b1156ec8720cbe3976bdb4242f71d"),
    ("0054_lab_instructions_md.py", 2031, "ce94d46eab8f7a0b5ce8e109291a66ca964fa9fe71418080e6721ffd92276bf5"),
    ("0055_lab_operations.py", 6946, "5f1befb9f90c0db8fe3944c545e5802dd8eeb21eea9b55868311a835833905c5"),
    ("0056_lab_instance_worker_grants.py", 6243, "fd75319dd804b8f0a388d0fde8f164421503d8e26b695c1c4459bed519e52aa7"),
    ("0057_lab_instance_name_unique.py", 4118, "a62e6765da087bff95c0f23431ef3e6b11a6eca9bde45c357b2ac644175bc849"),
    ("0058_lab_runtime_presence.py", 10723, "90b055ad7a308bb2a4f4413e54d1d73e4ab97fe8da41c07f59c1bd0d76fe6e49"),
    ("0059_lab_claim_owner.py", 6926, "a1d08823ab75bc8049dc86e1738fb52ae25b71e43f5f3d48b4134bdfa9810f1e"),
    ("0060_lab_conditional_ops.py", 12881, "a9d670de50e1c9d8d0048edcf6c98524372fe6b562e27278a3bf37612daa5937"),
    ("0061_lab_completion_grants.py", 1588, "e2da178268685378e46239391f0455cfb3937f1ee632254d9baf0600d31b3f65"),
    (
        "20260504_0001_initial_tenant_schema.py",
        15464,
        "33f9569bccc1562a2973df75e597332bb13b3003bab4d1815943e6cbee3eba3e",
    ),
    ("20260626_0002_courses.py", 3080, "89eae42c361a70b81bd2416b9c1338072b4be67788e6dfe76137e12f31fb53ca"),
    ("20260626_0003_cohorts.py", 2851, "eb479ff244a1d5b65f395a6c1f188c079a0f0e9db3f72e4d6dc253cb82cd06bb"),
    ("20260626_0004_assessment.py", 6540, "a118b1658abced245f04994afc0989ead3c203dc93c71a48d99bfd5c2008b5eb"),
    ("20260711_0034_entrance_resilience.py", 1860, "0b14733170a5c9cb84edb6be6e1c57e703851537f6447aa173bd2046e80b2554"),
    ("20260711_0035_applicant_profile.py", 2280, "d6bcfc0f7932cdb1aa8df3f2608e3a4911e32673512da3e3ea2533ed7d82fdc0"),
)
_ASSEMBLY = (
    ('a001_identity_extensions.py', 4749, 'e176281e63ef99a36b3715a886fe602af03b4b6bed33718198f6e0cb35922730'),
    ('a002_credential_reset_state.py', 1537, '73d0b4912eef3c1cfe23b05bdb624e556f169be709b057784b525943365ba71d'),
    ('a003_account_token_identity.py', 19922, 'd1f3ad5dde9ecd7379c1ddbdfcdf8f36102aae99009a83da9c8520db22e83bcb'),
    ('a004_retained_learning_refs.py', 1226, '2791a21d5c0a7dcfe628dc3b56360aecaa3b07b227a59ac69016b8c339c0d4ed'),
    ('a005_erp_completion_checkpoint.py', 1213, '5189ff695b2849409f8909545b39150d737f2dfd72b383d22b240d1572acd223'),
    ('a006_lab_claim_lease.py', 1203, 'adcfeaa21816f3580fd35f7851d8b7aa44bc2d6929d9925c74d87eab6d597601'),
    ('a007_lab_template_access.py', 1847, 'bf03d0289873e1772133ef7aa34692873b27d735aacf0a074fccc72557b24c2f'),
    ('a008_lab_console_activity.py', 4103, 'f80ec248ecdde8cb52c485d3a40641b0936d8aa02d9274feea841ec9e91e4662'),
    ('a009_applicant_bank_version_pin.py', 2280, '402724a0685fe9b3d147c4ae19f0e57ac2b8027d51bc16caa3a1b0251c906869'),
    ('a010_facilitator_nominations.py', 21176, '3139eeb4cd257cbdfc8b3b6e2f6babe57cdc51b4ff6b51c0fd114203fa95219a'),
)
_IDENTITY = tokens._FAMILIES
_RETAINED = (
    "account_tokens",
    "applicants",
    "email_outbox",
    "lab_templates",
    "lab_instances",
    "lab_operations",
    "notifications",
    "onboarding_tasks",
    "platform_settings",
    "tenant_entrance_defaults",
    "reminder_log",
    "reminder_preferences",
)
_NAMES = tuple(sorted((*history._SOURCE_NAMES, *_IDENTITY, *_RETAINED)))
_LOCK_NAMES = tuple(sorted((*_NAMES, "alembic_version")))
_STATE_KEY = object()
_HANDLES: WeakKeyDictionary[_Capture, ReferenceType[_State]] = WeakKeyDictionary()


class _Capture:
    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise ProductAdoptionRefused("Product history capture is privately issued")

    def __repr__(self):
        return "<AcademyProductHistory private unqualified capture>"


@dataclass(slots=True, weakref_slot=True, repr=False)
class _State:
    handle: _Capture
    connection: object
    root: object
    xid: object
    provenance: object = None
    oids: object = None
    catalogs: object = None
    cohorts: object = None
    learning_capture: object = None
    token_entry: object = None
    identity_association: object = None
    identity_verification: object = None
    token_association: object = None
    learning_association: object = None
    learning_raw: object = None
    completion_acks: object = None
    retained_fragment: object = None
    hosted_bindings: object = None
    hosted_context: object = None
    lock_oids: object = None
    retained_transition: object = None
    retained_runner: object = None
    checkpoint_transition: object = None
    checkpoint_runner: object = None
    lab_claim_transition: object = None
    lab_claim_runner: object = None
    phase: str = "captured"
    poisoned: bool = False
    retained_schema_unverified: bool = True
    checkpoint_unverified: bool = True
    lab_claim_unverified: bool = True


@dataclass(frozen=True, slots=True, repr=False)
class _Disposed:
    root: object = field(repr=False)


def _state_for(handle):
    _require(type(handle) is _Capture)
    pointer = _HANDLES.get(handle)
    state = None if pointer is None else pointer()
    _require(type(state) is _State and state.handle is handle)
    return cast(_State, state)


def _check(connection, handle, phase):
    state = _state_for(handle)
    _require(not state.poisoned and state.phase == phase)
    _require(isinstance(connection, Connection) and state.connection is connection)
    _require(_connection_preflight(connection) is state.root)
    _require(connection.info.get(_STATE_KEY) is state)
    _require(connection.scalar(sa.text("SELECT pg_catalog.txid_current()::text")) == state.xid)
    _retained_continuity(connection, state)
    return state


def _poison(connection, handle):
    if isinstance(connection, Connection):
        active = connection.info.get(_STATE_KEY)
        if type(active) is _State:
            active.poisoned = True
            hosted._poison_context(active.hosted_context, connection)
    if type(handle) is _Capture:
        pointer = _HANDLES.get(handle)
        state = None if pointer is None else pointer()
        if type(state) is _State:
            state.poisoned = True
            hosted._poison_context(state.hosted_context, connection)
    # Also poison the actual owned connection when no product handle was issued.
    hosted._poison_context(None, connection)


def _held_lockset(connection, oids):
    _require(type(oids) is tuple and tuple(name for name, _ in oids) == _LOCK_NAMES)
    _require(all(type(oid) is int and oid > 0 for _, oid in oids))
    held = set(
        connection.scalars(
            sa.text(
                "SELECT relation FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() "
                "AND locktype='relation' AND mode='AccessExclusiveLock' AND granted"
            )
        )
    )
    _require({oid for _, oid in oids} <= held)


def _retained_continuity(connection, state):
    """Conserve the initially qualified fragment; no new phase or baseline."""
    hosted._verify_context(state.hosted_context, connection, state.hosted_bindings)
    _held_lockset(connection, state.lock_oids)
    fragment = state.retained_fragment
    _require(type(fragment) is retained._RetainedFragment)
    _require(fragment.connection is connection and fragment.root is state.root)
    _require(fragment.physical_xid == state.xid)
    _require(
        tuple((table.name, table.oid) for table in fragment.tables)
        == tuple((name, dict(state.oids)[name]) for name, _, _ in retained._ROW_SPEC)
    )
    _require(retained._read_fixed_rows(connection) == fragment.tables)
    hosted._verify_context(state.hosted_context, connection, state.hosted_bindings)


def _inventory(directory, *, dynamic_dependencies=False):
    directory = Path(directory)
    entries = tuple(directory.iterdir())
    _require(all(path.name == "__pycache__" or (path.is_file() and path.suffix == ".py") for path in entries))
    files = tuple(sorted(path for path in entries if path.is_file()))
    _require(files and all(not path.is_symlink() for path in files))
    rows = []
    revisions = set()
    for path in files:
        raw = path.read_bytes()
        assigned = {}
        for node in ast.parse(raw).body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in {"revision", "down_revision", "depends_on"}:
                        _require(target.id not in assigned)
                        try:
                            assigned[target.id] = ast.literal_eval(cast(ast.AST, node.value))
                        except (ValueError, TypeError):
                            _require(dynamic_dependencies and target.id == "depends_on")
                            assigned[target.id] = ("expression", ast.dump(cast(ast.AST, node.value)))
        if path.name == "__init__.py":
            _require(not assigned)
        else:
            revision = assigned.get("revision")
            _require(type(revision) is str and revision not in revisions)
            revisions.add(revision)
        rows.append((path.name, len(raw), hashlib.sha256(raw).hexdigest(), tuple(sorted(assigned.items()))))
    return tuple(rows)


def _installed(name, directory):
    # Distribution identity + actual graph/bytes are continuity evidence only.
    # Deliberately do not retain direct_url: it may carry private credentials.
    distribution = metadata.distribution(name)
    inventory = _inventory(directory, dynamic_dependencies=True)
    return distribution.metadata["Name"], distribution.version, inventory


def _composed_graph(directories, inventories):
    # Learning's real bound prerequisite edges resolve against the entire
    # actual Kernel + Academy assembly + Learning graph, never owner slices.
    revision_ids = tuple(
        dict(row[3])["revision"] for inventory in inventories for row in inventory if row[0] != "__init__.py"
    )
    _require(len(revision_ids) == len(set(revision_ids)))
    scripts = ScriptDirectory(
        str(Path(directories[0]).parent), version_locations=[str(directory) for directory in directories]
    )
    graph = tuple(
        sorted((script.revision, script.down_revision, script.dependencies) for script in scripts.walk_revisions())
    )
    _require({row[0] for row in graph} == set(revision_ids))
    return graph, tuple(sorted(scripts.get_heads()))


def _provenance():
    root = Path(__file__).resolve().parents[2]
    frozen = _inventory(root / "alembic/versions")
    _require(tuple(row[:3] for row in frozen) == _FROZEN62)
    revisions = {dict(row[3])["revision"] for row in frozen}
    for row in frozen:
        assignments = dict(row[3])
        for name in ("down_revision", "depends_on"):
            parents = assignments.get(name)
            if parents is not None:
                parents = (parents,) if type(parents) is str else parents
                _require(type(parents) is tuple and all(parent in revisions for parent in parents))
    # Legacy custody remains exactly frozen62; successors belong to the assembly.
    referenced: set[str] = set()
    for row in frozen:
        parents = dict(row[3]).get("down_revision")
        referenced.update((parents,) if type(parents) is str else parents or ())
    _require({dict(row[3])["revision"] for row in frozen} - referenced == {"0061_lab_completion_grants"})
    assembly = _inventory(root / "alembic/identity_assembly_versions")
    _require(tuple(row[:3] for row in assembly) == _ASSEMBLY)
    _require(
        {dict(row[3])["revision"] for row in assembly}
        == {
            "a001_identity_extensions",
            "a002_credential_reset_state",
            "a003_account_token_identity",
            "a004_retained_learning_refs",
            "a005_erp_completion_checkpoint",
            "a006_lab_claim_lease",
            "a007_lab_template_access",
            "a008_lab_console_activity",
            "a009_applicant_bank_version_pin",
            "a010_facilitator_nominations",
        }
    )
    kernel_directory = Path(kernel_versions())
    learning_directory = Path(learning_versions())
    assembly_directory = root / "alembic/identity_assembly_versions"
    kernel = _installed("dotmac-kernel", kernel_directory)
    learning_owner = _installed("dotmac-learning", learning_directory)
    graph = _composed_graph(
        (kernel_directory, assembly_directory, learning_directory), (kernel[2], assembly, learning_owner[2])
    )
    return frozen, assembly, kernel, learning_owner, graph


def _cohort(connection, name, schema):
    # Fixed identifier-only projection: never retrieve credential/token material.
    key = "key" if name == "platform_settings" else "tenant_id" if name == "tenant_entrance_defaults" else "id"
    return history._query(connection, f'SELECT "{key}" FROM "{schema}"."{name}" ORDER BY "{key}"')  # noqa: S608


def _identity_catalog(catalog, token_oid):
    # Only a003's token-owned incoming RI facts may change during this slice.
    return replace(
        catalog,
        incoming=tuple(row for row in catalog.incoming if row[2] != token_oid),
        triggers=tuple(row for row in catalog.triggers if not row[5] or row[7] != token_oid),
    )


def _continuity(connection, state):
    _retained_continuity(connection, state)
    _require(_provenance() == state.provenance)
    oids = dict(state.oids)
    if state.phase in ("a006 recorded", "lab claim lease adopted, final admission pending"):
        _verify_retained_prerequisites(connection, state)
        lab_claim._verify_after(connection, state, state.lab_claim_transition, recorded=True)
        if state.phase == "lab claim lease adopted, final admission pending":
            _require(transition._version_rows(connection) == state.lab_claim_transition.after_versions)
        _retained_continuity(connection, state)
        return
    if state.phase in ("a005 recorded", "checkpoint adopted, final admission pending"):
        _verify_retained_prerequisites(connection, state)
        checkpoint._verify_after(connection, state, state.checkpoint_transition, recorded=True)
        if state.phase == "checkpoint adopted, final admission pending":
            _require(transition._version_rows(connection) == state.checkpoint_transition.after_versions)
        _retained_continuity(connection, state)
        return
    if state.phase in ("a004 recorded", "retained adopted, checkpoint pending"):
        _verify_retained_prerequisites(connection, state)
        transition._verify_after(connection, state, state.retained_transition, recorded=True)
        if state.phase == "retained adopted, checkpoint pending":
            _require(transition._version_rows(connection) == state.retained_transition.after_versions)
        _retained_continuity(connection, state)
        return
    _require(state.phase not in ("a004 executing", "a005 executing", "a006 executing"))
    token_catalog = None if state.token_association is None else state.token_association[2]
    if state.token_association is not None:
        tokens._conservation(connection, state.token_association[0], after_creation=True)
    for name, captured in state.catalogs:
        schema = "academy_identity_compat" if name in _IDENTITY and state.identity_association is not None else "public"
        _require(history._oid(connection, name, schema) == oids[name])
        _require(_cohort(connection, name, schema) == dict(state.cohorts)[name])
        current = history._catalog(connection, oids[name])
        if name == "account_tokens" and token_catalog is not None:
            _require(tokens._catalog(connection) == token_catalog)
            _require(current == state.token_association[3])
            continue
        if name in _IDENTITY:
            captured = _identity_catalog(captured, oids["account_tokens"])
            current = _identity_catalog(current, oids["account_tokens"])
        _require(current == captured)
    if state.learning_capture is not None:
        history._verify_source(connection, state.learning_capture)
    _retained_continuity(connection, state)


def _capture_product_history(connection: Connection, bindings=None, *, _hosted_context=None) -> _Capture:
    """Initial gated evidence only; final composed adoption stays unqualified."""
    state = None
    handle = None
    root = None
    try:
        _require(isinstance(connection, Connection))
        root = _connection_preflight(connection)
        previous = connection.info.get(_STATE_KEY)
        if previous is not None:
            _require(type(previous) in (_State, _Disposed))
            _require(previous.root is not root and not previous.root.is_active)
            if type(previous) is _State:
                _dispose_product_history(connection, previous.handle)
            connection.info.pop(_STATE_KEY, None)
        # Even a pre-issuance refusal is terminal for this actual caller root.
        connection.info[_STATE_KEY] = _Disposed(root)
        _require(len(_NAMES) == len(set(_NAMES)) == 47)
        oids = tuple((name, history._oid(connection, name)) for name in _LOCK_NAMES)
        _held_lockset(connection, oids)
        provenance = _provenance()
        _require(type(bindings) is environment.HostedEnvironmentBindings)
        hosted._verify_context(_hosted_context, connection, bindings)
        # Both REAL Genesis gates run before digest capture or product issuance.
        fragment = retained._capture_retained_rows(connection, bindings, _hosted_context=_hosted_context)
        hosted._verify_context(_hosted_context, connection, bindings)
        xid = connection.scalar(sa.text("SELECT pg_catalog.txid_current()::text"))
        _require(fragment.connection is connection and fragment.root is root and fragment.physical_xid == xid)
        handle = object.__new__(_Capture)
        state = _State(
            handle,
            connection,
            root,
            xid,
            retained_fragment=fragment,
            hosted_bindings=bindings,
            hosted_context=_hosted_context,
            lock_oids=oids,
        )
        connection.info[_STATE_KEY] = state
        _HANDLES[handle] = ref(state)
        state.provenance = provenance
        state.oids = tuple((name, oid) for name, oid in oids if name != "alembic_version")
        state.catalogs = tuple((name, history._catalog(connection, oid)) for name, oid in state.oids)
        for _, catalog in state.catalogs:
            _require(catalog.relation[1:3] == ("r", "app_admin"))
            _require(
                connection.scalar(
                    sa.text(
                        "SELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT') "
                        "AND NOT pg_catalog.row_security_active(:oid)"
                    ),
                    {"oid": catalog.relation[0]},
                )
                is True
            )
        state.cohorts = tuple((name, _cohort(connection, name, "public")) for name in _NAMES)
        old_token = tokens._issued(connection)
        _require(old_token is None or (old_token.entry.root is not root and not old_token.entry.root.is_active))
        state.learning_capture = history._capture_learning_history(connection)
        state.token_entry = tokens.capture_historical_account_tokens(connection)
        _continuity(connection, state)
        _check(connection, handle, "captured")
        return handle
    except BaseException as error:
        _poison(connection, handle)
        hosted._poison_context(_hosted_context, connection)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy product capture refused; root rollback required") from None


@dataclass(slots=True, repr=False)
class _IdentityVerification:
    decoder: AcademyIdentityHistoryDecoder = field(repr=False)
    expected: object = field(repr=False)
    operation: object = field(repr=False)
    registry: object = field(repr=False)
    versions: object = field(repr=False)
    bindings: object = field(repr=False)
    snapshot: object = field(default=None, repr=False)
    receipt: object = field(default=None, repr=False)


def _register_identity_import(
    connection, decoder, expected, operation, *, module_registry=None, module_versions=None, prerequisite_bindings=()
):
    """Only the genuine import adapter registers its decoder BEFORE writes."""
    state = connection.info.get(_STATE_KEY)
    if state is None:
        return  # Standalone comparison issues no product association.
    try:
        _require(type(state) is _State)
        state = cast(_State, state)
        _check(connection, state.handle, "captured")
        from app.maintenance.identity_history import AcademyIdentityHistoryDecoder

        _require(type(decoder) is AcademyIdentityHistoryDecoder and decoder._connection is None)
        _require(state.identity_verification is None)
        _require(type(prerequisite_bindings) is tuple)
        state.identity_verification = _IdentityVerification(
            decoder,
            expected,
            operation,
            module_registry,
            None if module_versions is None else tuple(sorted(module_versions.items())),
            prerequisite_bindings,
        )
    except BaseException:
        _poison(connection, None)
        raise


def _capture_identity_decoder(connection, decoder: AcademyIdentityHistoryDecoder):
    state = connection.info.get(_STATE_KEY)
    if type(state) is not _State:
        return
    association = state.identity_verification
    if type(association) is not _IdentityVerification or association.decoder is not decoder:
        return  # An independent preservation reader cannot change expectations.
    try:
        _check(connection, state.handle, "captured")
        _require(association.snapshot is None and association.receipt is None)
        _require(decoder._connection is connection and decoder._root is state.root)
        _require(decoder._snapshot is not None)
        association.snapshot = decoder._snapshot
    except BaseException:
        _poison(connection, state.handle)
        raise


def _complete_identity_import(connection, decoder, receipt):
    state = connection.info.get(_STATE_KEY)
    if state is None:
        return
    try:
        _require(type(state) is _State)
        state = cast(_State, state)
        _check(connection, state.handle, "captured")
        association = state.identity_verification
        _require(type(association) is _IdentityVerification and association.decoder is decoder)
        association = cast(_IdentityVerification, association)
        _require(association.snapshot is decoder._snapshot and association.snapshot is not None)
        _require(association.receipt is None)
        association.receipt = receipt
    except BaseException:
        _poison(connection, None)
        raise


def _verify_identity_import(connection, handle):
    """No phase advancement: genuine registered pre-write association only."""
    try:
        state = _state_for(handle)
        _require(not state.poisoned)
        _check(connection, handle, state.phase)
        association = state.identity_verification
        _require(type(association) is _IdentityVerification and association.receipt is not None)
        _require(association.snapshot is association.decoder._snapshot)
        issued = tokens._issued(connection)
        if issued is None and state.token_association is not None:
            issued = state.token_association[0]
            _require(state.identity_association is not None and issued is state.identity_association[2])
        _require(issued is not None and issued.entry is state.token_entry and issued.imported is not None)
        _require(issued.imported[0] is association.expected and issued.imported[1] is association.receipt)
        from app.maintenance.identity_history import _verify_identity_import_data

        _verify_identity_import_data(
            connection,
            association.decoder,
            association.expected,
            association.operation,
            association.receipt,
            module_registry=association.registry,
            module_versions=None if association.versions is None else dict(association.versions),
            prerequisite_bindings=association.bindings,
        )
        _check(connection, handle, state.phase)
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy identity verification refused; root rollback required") from None


def _observe_identity_import(connection: Connection, handle: _Capture) -> None:
    """Direct successful owner association BEFORE a003 consumes its state."""
    try:
        state = _check(connection, handle, "captured")
        _verify_identity_import(connection, handle)
        issued = tokens._issued(connection)
        _require(issued is not None and issued.entry is state.token_entry)
        _require(issued.entry.connection is connection and issued.entry.root is state.root)
        _require(issued.entry.historical and not issued.consumed and issued.imported is not None)
        expected, receipt = issued.imported
        _require(receipt is not None)
        for name in _IDENTITY:
            _require(getattr(expected.relations, name) == dict(state.oids)[name])
            _require(getattr(expected.cohort, name) == frozenset(row[0] for row in dict(state.cohorts)[name]))
        history._observe_identity_relocation(connection, state.learning_capture)
        state.identity_association = (expected, receipt, issued)
        _continuity(connection, state)
        _check(connection, handle, "captured")
        state.phase = "identity observed"
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy product identity observation refused; root rollback required") from None


def _observe_account_token_adoption(connection: Connection, handle: _Capture) -> None:
    """Call the genuine immediate a003 receipt; no supplied receipt is accepted."""
    try:
        state = _check(connection, handle, "identity observed")
        _verify_identity_import(connection, handle)
        issued = tokens._issued(connection)
        _require(issued is state.identity_association[2] and issued.final is not None)
        final = issued.final
        receipt = tokens.account_token_identity_receipt(connection, state.token_entry)
        _require(receipt.identity_import_receipt is state.identity_association[1])
        full_catalog = history._catalog(connection, dict(state.oids)["account_tokens"])
        state.token_association = (issued, receipt, final, full_catalog)
        _continuity(connection, state)
        _check(connection, handle, "identity observed")
        _verify_identity_import(connection, handle)
        state.phase = "token observed"
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy product token observation refused; root rollback required") from None


def _import_and_seal_learning(connection: Connection, handle: _Capture) -> None:
    """Actual released owner import + independent verify, then release source.

    The result is ONLY 'Learning sealed, retained adoption pending'. Full raw
    Learning cohorts, original catalogs and every nullable ACK remain private.
    """
    try:
        state = _check(connection, handle, "token observed")
        _verify_identity_import(connection, handle)
        _continuity(connection, state)
        captured = history._verify_source(connection, state.learning_capture)
        snapshot = history._export_learning_history(connection, state.learning_capture)
        acks = history._completion_ack_history(connection, state.learning_capture)
        observation = learning.import_snapshot_v5(connection, snapshot)
        _continuity(connection, state)
        verification = history._verify_canonical_learning_history(connection, state.learning_capture)
        _continuity(connection, state)
        _require(verification.version == 5 and verification.tenant_ids == snapshot.tenant_ids)
        _require({row.table for row in verification.row_counts} == set(history._SOURCE_NAMES))
        _require(verification == observation.verification)
        _require(history._completion_ack_history(connection, state.learning_capture) == acks)
        state.learning_raw = captured.raw_rows
        state.completion_acks = acks
        state.learning_association = (snapshot, observation, verification)
        _check(connection, handle, "token observed")
        history._release_learning_history(connection, state.learning_capture)
        state.learning_capture = None
        _verify_identity_import(connection, handle)
        state.phase = "Learning sealed, retained adoption pending"
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy product Learning seal refused; root rollback required") from None


def _dispose_product_history(connection: Connection, handle: _Capture) -> None:
    """Clear private material; never commit/rollback or grant another phase."""
    state = _state_for(handle)
    _require(state.connection is connection and connection.info.get(_STATE_KEY) is state)
    root = state.root
    hosted._poison_context(state.hosted_context, connection)
    try:
        if state.learning_capture is not None:
            history._release_learning_history(connection, state.learning_capture)
    finally:
        _HANDLES.pop(handle, None)
        association = state.identity_verification
        if type(association) is _IdentityVerification:
            decoder = association.decoder
            decoder._snapshot = None
            decoder._accounts = ()
            decoder._policies = ()
            decoder._connection = None
            decoder._root = None
            for name in _IdentityVerification.__dataclass_fields__:
                setattr(association, name, None)
        pending = state.retained_transition
        if type(pending) is transition._RetainedTransition:
            for name in transition._RetainedTransition.__dataclass_fields__:
                setattr(pending, name, None)
        pending_checkpoint = state.checkpoint_transition
        if type(pending_checkpoint) is checkpoint._CheckpointTransition:
            for name in checkpoint._CheckpointTransition.__dataclass_fields__:
                setattr(pending_checkpoint, name, None)
        pending_lab_claim = state.lab_claim_transition
        if type(pending_lab_claim) is lab_claim._LabClaimLeaseTransition:
            for name in lab_claim._LabClaimLeaseTransition.__dataclass_fields__:
                setattr(pending_lab_claim, name, None)
        for name in _State.__dataclass_fields__:
            setattr(state, name, None)
        connection.info[_STATE_KEY] = _Disposed(root)


def _verify_retained_prerequisites(connection, state):
    """Re-use original owner captures; a released Learning handle stays released."""
    _require(state.learning_capture is None and state.learning_association is not None)
    _require(state.identity_association is not None and state.token_association is not None)
    _verify_identity_import(connection, state.handle)
    issued = state.token_association[0]
    _require(issued is state.identity_association[2] and issued.entry is state.token_entry)
    tokens._conservation(connection, issued, after_creation=True)
    _require(learning.verify_snapshot_v5(connection, state.learning_association[0]) == state.learning_association[2])
    _require(
        tuple((spec.name, history._raw_projection(connection, spec)) for spec in history._TABLES) == state.learning_raw
    )
    _require(state.completion_acks is not None)
    _retained_continuity(connection, state)


def _prepare_retained_transition(connection: Connection, handle: _Capture) -> None:
    """Privately prepare historical a004; no caller catalog/map/flag is accepted."""
    try:
        state = _check(connection, handle, "Learning sealed, retained adoption pending")
        _require(state.retained_runner is not None)
        _require(state.retained_transition is None and state.retained_schema_unverified)
        _continuity(connection, state)
        _verify_retained_prerequisites(connection, state)
        pending = transition._prepare(connection, state)
        _check(connection, handle, "Learning sealed, retained adoption pending")
        state.retained_transition = pending
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a004 preparation refused; root rollback required") from None


def _consume_retained_transition(connection: Connection) -> transition._RetainedTransition:
    """a004 consumes the exact privately stored object BEFORE the first DDL."""
    try:
        state = connection.info.get(_STATE_KEY)
        _require(type(state) is _State)
        state = cast(_State, state)
        _check(connection, state.handle, "Learning sealed, retained adoption pending")
        pending = state.retained_transition
        _require(type(pending) is transition._RetainedTransition and not pending.consumed and pending.final is None)
        pending = cast(transition._RetainedTransition, pending)
        _require(state.retained_runner is not None and pending.runner is state.retained_runner)
        _require(pending.handle is state.handle and pending.connection is connection)
        _require(
            pending.root is state.root and pending.xid == state.xid and pending.fragment is state.retained_fragment
        )
        # Irreversible private consumption comes before revalidation or DDL.
        pending.consumed = True
        _continuity(connection, state)
        _verify_retained_prerequisites(connection, state)
        transition._verify_before(connection, pending)
        _check(connection, state.handle, "Learning sealed, retained adoption pending")
        state.phase = "a004 executing"
        return pending
    except BaseException as error:
        _poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a004 consumption refused; root rollback required") from None


def _record_retained_transition(connection: Connection, entry: transition._RetainedTransition) -> None:
    """Independent final graph/conservation check; no partial-DDL continuity."""
    try:
        state = connection.info.get(_STATE_KEY)
        _require(type(state) is _State and state.retained_transition is entry)
        state = cast(_State, state)
        _check(connection, state.handle, "a004 executing")
        _require(state.retained_runner is not None and entry.runner is state.retained_runner)
        _require(entry.consumed and entry.final is None and entry.handle is state.handle)
        _require(entry.connection is connection and entry.root is state.root and entry.xid == state.xid)
        _require(_provenance() == state.provenance)
        _verify_retained_prerequisites(connection, state)
        _require(transition._version_rows(connection) == entry.before_versions)
        packet, fks, triggers = transition._verify_after(connection, state, entry, recorded=False)
        entry.final, entry.new_fks, entry.new_triggers = packet, fks, triggers
        _check(connection, state.handle, "a004 executing")
        state.phase = "a004 recorded"
    except BaseException as error:
        _poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a004 recording refused; root rollback required") from None


def _observe_retained_transition(connection: Connection, handle: _Capture) -> None:
    """Immediately observe actual complete Alembic rows after a004 returns."""
    try:
        state = _check(connection, handle, "a004 recorded")
        entry = state.retained_transition
        _require(type(entry) is transition._RetainedTransition and entry.consumed and entry.final is not None)
        _require(state.retained_runner is not None and entry.runner is state.retained_runner)
        _require(
            entry.handle is handle
            and entry.connection is connection
            and entry.root is state.root
            and entry.xid == state.xid
        )
        _require(_provenance() == state.provenance)
        _require(history._oid(connection, "alembic_version") == entry.version_oid)
        _require(transition._version_rows(connection) == entry.after_versions)
        _continuity(connection, state)
        _check(connection, handle, "a004 recorded")
        state.phase = "retained adopted, checkpoint pending"
        state.retained_schema_unverified = False
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a004 observation refused; root rollback required") from None


def _run_retained_transition(connection: Connection, handle: _Capture) -> None:
    """One private exception boundary includes Alembic's actual version write.

    Construct the genuine ordinary full-graph Config here. No caller config,
    expected heads, catalog, receipt or success flag may authorize this runner.
    """
    state = None
    invocation = object()
    try:
        state = _check(connection, handle, "Learning sealed, retained adoption pending")
        _require(state.retained_runner is None and state.retained_transition is None)
        config = ordinary_migration_config()
        config.attributes["connection"] = connection
        locations = tuple(map(Path, config.attributes["academy_migration_locations"]))
        expected_locations = {Path(kernel_versions()).resolve(), Path(learning_versions()).resolve(),
                              (Path(__file__).resolve().parents[2] / "alembic/identity_assembly_versions").resolve()}
        _require(set(locations) == expected_locations and len(locations) == 3)
        scripts = ScriptDirectory.from_config(config)
        _require({Path(path).resolve() for path in scripts.version_locations} == expected_locations)
        graph = tuple(sorted((script.revision, script.down_revision, script.dependencies)
                             for script in scripts.walk_revisions()))
        _require((graph, tuple(sorted(scripts.get_heads()))) == state.provenance[4])
        _require(_provenance() == state.provenance and config.attributes["connection"] is connection)
        state.retained_runner = invocation
        _prepare_retained_transition(connection, handle)
        command.upgrade(config, transition._A004)
        _require(config.attributes["connection"] is connection)
        _observe_retained_transition(connection, handle)
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy retained runner refused; root rollback required") from None
    finally:
        if type(state) is _State and state.retained_runner is invocation:
            state.retained_runner = None


def _prepare_checkpoint_transition(connection: Connection, handle: _Capture) -> None:
    """Privately prepare inert a005 after observed a004; no caller input."""
    try:
        state = _check(connection, handle, "retained adopted, checkpoint pending")
        _require(state.checkpoint_runner is not None)
        _require(state.checkpoint_transition is None and state.checkpoint_unverified)
        _require(not state.retained_schema_unverified)
        _require(type(state.retained_transition) is transition._RetainedTransition)
        _require(state.retained_transition.final is not None)
        _continuity(connection, state)
        _verify_retained_prerequisites(connection, state)
        pending = checkpoint._prepare(connection, state)
        _check(connection, handle, "retained adopted, checkpoint pending")
        state.checkpoint_transition = pending
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a005 preparation refused; root rollback required") from None


def _consume_checkpoint_transition(connection: Connection) -> checkpoint._CheckpointTransition:
    """a005 consumes the exact privately stored object BEFORE the first effect."""
    try:
        state = connection.info.get(_STATE_KEY)
        _require(type(state) is _State)
        state = cast(_State, state)
        _check(connection, state.handle, "retained adopted, checkpoint pending")
        pending = state.checkpoint_transition
        _require(type(pending) is checkpoint._CheckpointTransition and not pending.consumed and pending.final is None)
        pending = cast(checkpoint._CheckpointTransition, pending)
        _require(state.checkpoint_runner is not None and pending.runner is state.checkpoint_runner)
        _require(pending.retained_entry is state.retained_transition)
        _require(pending.handle is state.handle and pending.connection is connection)
        _require(pending.root is state.root and pending.xid == state.xid)
        # Irreversible private consumption comes before revalidation or DDL.
        pending.consumed = True
        _continuity(connection, state)
        _verify_retained_prerequisites(connection, state)
        checkpoint._verify_before(connection, pending)
        _check(connection, state.handle, "retained adopted, checkpoint pending")
        state.phase = "a005 executing"
        return pending
    except BaseException as error:
        _poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a005 consumption refused; root rollback required") from None


def _record_checkpoint_transition(connection: Connection, entry: checkpoint._CheckpointTransition) -> None:
    """Independent checkpoint/conservation check; no partial-effect continuity."""
    try:
        state = connection.info.get(_STATE_KEY)
        _require(type(state) is _State and state.checkpoint_transition is entry)
        state = cast(_State, state)
        _check(connection, state.handle, "a005 executing")
        _require(state.checkpoint_runner is not None and entry.runner is state.checkpoint_runner)
        _require(entry.consumed and entry.final is None and entry.handle is state.handle)
        _require(entry.connection is connection and entry.root is state.root and entry.xid == state.xid)
        _require(entry.retained_entry is state.retained_transition)
        _require(_provenance() == state.provenance)
        _verify_retained_prerequisites(connection, state)
        _require(history._oid(connection, "alembic_version") == entry.version_oid)
        _require(transition._version_rows(connection) == entry.before_versions)
        final, fks, triggers = checkpoint._verify_after(connection, state, entry, recorded=False)
        entry.final, entry.new_fks, entry.new_triggers = final, fks, triggers
        _check(connection, state.handle, "a005 executing")
        state.phase = "a005 recorded"
    except BaseException as error:
        _poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a005 recording refused; root rollback required") from None


def _observe_checkpoint_transition(connection: Connection, handle: _Capture) -> None:
    """Immediately observe actual complete Alembic rows after a005 returns."""
    try:
        state = _check(connection, handle, "a005 recorded")
        entry = state.checkpoint_transition
        _require(type(entry) is checkpoint._CheckpointTransition and entry.consumed and entry.final is not None)
        _require(state.checkpoint_runner is not None and entry.runner is state.checkpoint_runner)
        _require(
            entry.handle is handle
            and entry.connection is connection
            and entry.root is state.root
            and entry.xid == state.xid
        )
        _require(entry.retained_entry is state.retained_transition)
        _require(_provenance() == state.provenance)
        _require(history._oid(connection, "alembic_version") == entry.version_oid)
        _require(transition._version_rows(connection) == entry.after_versions)
        _continuity(connection, state)
        _check(connection, handle, "a005 recorded")
        state.phase = "checkpoint adopted, final admission pending"
        state.checkpoint_unverified = False
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a005 observation refused; root rollback required") from None


def _run_checkpoint_transition(connection: Connection, handle: _Capture) -> None:
    """One private exception boundary includes Alembic's actual version write.

    Construct the genuine ordinary full-graph Config here. No caller config,
    expected heads, catalog, receipt or success flag may authorize this runner.
    The result is ONLY 'checkpoint adopted, final admission pending'.
    """
    state = None
    invocation = object()
    try:
        state = _check(connection, handle, "retained adopted, checkpoint pending")
        _require(state.checkpoint_runner is None and state.checkpoint_transition is None)
        _require(not state.retained_schema_unverified and state.checkpoint_unverified)
        config = ordinary_migration_config()
        config.attributes["connection"] = connection
        locations = tuple(map(Path, config.attributes["academy_migration_locations"]))
        expected_locations = {
            Path(kernel_versions()).resolve(),
            Path(learning_versions()).resolve(),
            (Path(__file__).resolve().parents[2] / "alembic/identity_assembly_versions").resolve(),
        }
        _require(set(locations) == expected_locations and len(locations) == 3)
        scripts = ScriptDirectory.from_config(config)
        _require({Path(path).resolve() for path in scripts.version_locations} == expected_locations)
        graph = tuple(
            sorted((script.revision, script.down_revision, script.dependencies) for script in scripts.walk_revisions())
        )
        _require((graph, tuple(sorted(scripts.get_heads()))) == state.provenance[4])
        _require(_provenance() == state.provenance and config.attributes["connection"] is connection)
        state.checkpoint_runner = invocation
        _prepare_checkpoint_transition(connection, handle)
        command.upgrade(config, checkpoint._A005)
        _require(config.attributes["connection"] is connection)
        _observe_checkpoint_transition(connection, handle)
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy checkpoint runner refused; root rollback required") from None
    finally:
        if type(state) is _State and state.checkpoint_runner is invocation:
            state.checkpoint_runner = None


def _prepare_lab_claim_lease_transition(connection: Connection, handle: _Capture) -> None:
    """Privately prepare a006 after observed a005; no caller input."""
    try:
        state = _check(connection, handle, "checkpoint adopted, final admission pending")
        _require(state.lab_claim_runner is not None)
        _require(state.lab_claim_transition is None and state.lab_claim_unverified)
        _require(not state.retained_schema_unverified and not state.checkpoint_unverified)
        _require(type(state.checkpoint_transition) is checkpoint._CheckpointTransition)
        _require(state.checkpoint_transition.final is not None)
        _continuity(connection, state)
        _verify_retained_prerequisites(connection, state)
        pending = lab_claim._prepare(connection, state)
        _check(connection, handle, "checkpoint adopted, final admission pending")
        state.lab_claim_transition = pending
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a006 preparation refused; root rollback required") from None


def _consume_lab_claim_lease_transition(connection: Connection) -> lab_claim._LabClaimLeaseTransition:
    """a006 consumes the exact privately stored object BEFORE the first effect."""
    try:
        state = connection.info.get(_STATE_KEY)
        _require(type(state) is _State)
        state = cast(_State, state)
        _check(connection, state.handle, "checkpoint adopted, final admission pending")
        pending = state.lab_claim_transition
        _require(type(pending) is lab_claim._LabClaimLeaseTransition and not pending.consumed and pending.final is None)
        pending = cast(lab_claim._LabClaimLeaseTransition, pending)
        _require(state.lab_claim_runner is not None and pending.runner is state.lab_claim_runner)
        _require(pending.checkpoint_entry is state.checkpoint_transition)
        _require(pending.handle is state.handle and pending.connection is connection)
        _require(pending.root is state.root and pending.xid == state.xid)
        # Irreversible private consumption comes before revalidation or DDL.
        pending.consumed = True
        _continuity(connection, state)
        _verify_retained_prerequisites(connection, state)
        lab_claim._verify_before(connection, pending)
        _check(connection, state.handle, "checkpoint adopted, final admission pending")
        state.phase = "a006 executing"
        return pending
    except BaseException as error:
        _poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a006 consumption refused; root rollback required") from None


def _record_lab_claim_lease_transition(connection: Connection, entry: lab_claim._LabClaimLeaseTransition) -> None:
    """Independent claim-lease/conservation check; no partial-effect continuity."""
    try:
        state = connection.info.get(_STATE_KEY)
        _require(type(state) is _State and state.lab_claim_transition is entry)
        state = cast(_State, state)
        _check(connection, state.handle, "a006 executing")
        _require(state.lab_claim_runner is not None and entry.runner is state.lab_claim_runner)
        _require(entry.consumed and entry.final is None and entry.handle is state.handle)
        _require(entry.connection is connection and entry.root is state.root and entry.xid == state.xid)
        _require(entry.checkpoint_entry is state.checkpoint_transition)
        _require(_provenance() == state.provenance)
        _verify_retained_prerequisites(connection, state)
        _require(history._oid(connection, "alembic_version") == entry.version_oid)
        _require(transition._version_rows(connection) == entry.before_versions)
        final, attnum, check_oids = lab_claim._verify_after(connection, state, entry, recorded=False)
        entry.final, entry.new_attnum, entry.new_check_oids = final, attnum, check_oids
        _check(connection, state.handle, "a006 executing")
        state.phase = "a006 recorded"
    except BaseException as error:
        _poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a006 recording refused; root rollback required") from None


def _observe_lab_claim_lease_transition(connection: Connection, handle: _Capture) -> None:
    """Immediately observe actual complete Alembic rows after a006 returns."""
    try:
        state = _check(connection, handle, "a006 recorded")
        entry = state.lab_claim_transition
        _require(type(entry) is lab_claim._LabClaimLeaseTransition and entry.consumed and entry.final is not None)
        _require(state.lab_claim_runner is not None and entry.runner is state.lab_claim_runner)
        _require(
            entry.handle is handle
            and entry.connection is connection
            and entry.root is state.root
            and entry.xid == state.xid
        )
        _require(entry.checkpoint_entry is state.checkpoint_transition)
        _require(_provenance() == state.provenance)
        _require(history._oid(connection, "alembic_version") == entry.version_oid)
        _require(transition._version_rows(connection) == entry.after_versions)
        _continuity(connection, state)
        _check(connection, handle, "a006 recorded")
        state.phase = "lab claim lease adopted, final admission pending"
        state.lab_claim_unverified = False
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy a006 observation refused; root rollback required") from None


def _run_lab_claim_lease_transition(connection: Connection, handle: _Capture) -> None:
    """One private exception boundary includes Alembic's actual version write.

    Construct the genuine ordinary full-graph Config here. No caller config,
    expected heads, catalog, receipt or success flag may authorize this runner.
    The result is ONLY 'lab claim lease adopted, final admission pending'.
    """
    state = None
    invocation = object()
    try:
        state = _check(connection, handle, "checkpoint adopted, final admission pending")
        _require(state.lab_claim_runner is None and state.lab_claim_transition is None)
        _require(not state.retained_schema_unverified and not state.checkpoint_unverified)
        _require(state.lab_claim_unverified)
        config = ordinary_migration_config()
        config.attributes["connection"] = connection
        locations = tuple(map(Path, config.attributes["academy_migration_locations"]))
        expected_locations = {
            Path(kernel_versions()).resolve(),
            Path(learning_versions()).resolve(),
            (Path(__file__).resolve().parents[2] / "alembic/identity_assembly_versions").resolve(),
        }
        _require(set(locations) == expected_locations and len(locations) == 3)
        scripts = ScriptDirectory.from_config(config)
        _require({Path(path).resolve() for path in scripts.version_locations} == expected_locations)
        graph = tuple(
            sorted((script.revision, script.down_revision, script.dependencies) for script in scripts.walk_revisions())
        )
        _require((graph, tuple(sorted(scripts.get_heads()))) == state.provenance[4])
        _require(_provenance() == state.provenance and config.attributes["connection"] is connection)
        state.lab_claim_runner = invocation
        _prepare_lab_claim_lease_transition(connection, handle)
        command.upgrade(config, lab_claim._A006)
        _require(config.attributes["connection"] is connection)
        _observe_lab_claim_lease_transition(connection, handle)
    except BaseException as error:
        _poison(connection, handle)
        if not isinstance(error, Exception):
            raise
        raise ProductAdoptionRefused("Academy lab claim lease runner refused; root rollback required") from None
    finally:
        if type(state) is _State and state.lab_claim_runner is invocation:
            state.lab_claim_runner = None
