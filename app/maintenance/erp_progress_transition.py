"""One-use ERP successor continuation bound to a genuine observed a006 root.

The staged observer proves finite deltas. This module owns orchestration and
exception poisoning, including Alembic callbacks and final version writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import sqlalchemy as sa

from alembic import command
from app.maintenance import account_token_identity as tokens
from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import erp_successor_catalog as catalog
from app.maintenance import learning_history as history
from app.maintenance import retained_transition as retained
from app.maintenance.identity_history import _connection_preflight
from app.migration_graph import ordinary_migration_config

_A011 = "a011_erp_progress_checkpoint"
_STAGES = (
    "a007_lab_template_access",
    "a008_lab_console_activity",
    "a009_applicant_bank_version_pin",
    "a010_facilitator_nominations",
)
_KEY = object()


def _require(condition):
    if not condition:
        from app.maintenance.product_adoption import ProductAdoptionRefused

        raise ProductAdoptionRefused("Academy ERP successor refused; root rollback required")


@dataclass(slots=True, repr=False)
class _Continuation:
    connection: object
    root: object
    physical: tuple
    roles: tuple
    provenance: tuple
    version_oid: int
    owner: object
    historical: bool
    runner: object
    original_acks: tuple
    checkpoint_oid: int
    completion_oid: int
    packet: dict = field(repr=False)
    next_stage: int = 0
    consumed: bool = False
    recorded: bool = False
    row_packet: dict | None = field(default=None, repr=False)
    row_oracle: tuple | None = field(default=None, repr=False)
    poisoned: bool = False

    def __new__(cls, *args, **kwargs):
        raise RuntimeError("ERP continuation is privately issued")


def _roles(connection):
    return history._query(connection, "SELECT current_user,session_user")


def _check(connection, entry):
    from app.maintenance import fresh_product as fresh
    from app.maintenance import product_adoption as product

    _require(type(entry) is _Continuation and connection.info.get(_KEY) is entry)
    _require(not entry.poisoned and entry.connection is connection and entry.runner is not None)
    _require(_connection_preflight(connection) is entry.root and tokens._physical_context(connection) == entry.physical)
    _require(_roles(connection) == entry.roles and product._provenance() == entry.provenance)
    _require(history._oid(connection, "alembic_version") == entry.version_oid)
    _require(history._oid(connection, checkpoint._TABLE) == entry.checkpoint_oid)
    _require(history._oid(connection, "course_completions", "mod_learning") == entry.completion_oid)
    checkpoint._held(connection, {entry.checkpoint_oid, entry.completion_oid, entry.version_oid})
    if entry.historical:
        state = product._state_for(entry.owner)
        _require(state.connection is connection and state.root is entry.root and not state.poisoned)
        _require(connection.info.get(product._STATE_KEY) is state)
        # Fixed historical row projection omits only the explicitly added source
        # attributes; it does not manufacture a post-a006 catalog baseline.
        product._retained_continuity(connection, state)
        _require(state.checkpoint_transition.raw_acks == entry.original_acks)
        _require(checkpoint._source_acks(connection) == entry.original_acks)
    else:
        fresh._check(connection, entry.owner)
        _require(entry.owner.prepared and entry.owner.next_stage == len(fresh._STAGES))
        _require(entry.original_acks == ())
    _require(checkpoint._canonical_keys(connection) == tuple((t, i) for t, i, _ in entry.original_acks))
    _require(checkpoint._checkpoint_rows(connection) == entry.original_acks)


def _poison(connection, entry):
    from app.maintenance import product_adoption as product

    if type(entry) is not _Continuation:
        product._poison(connection, None)
        from app.maintenance import fresh_product as fresh

        issued = fresh._issued(connection)
        if type(issued) is fresh._Entry:
            issued.poisoned = True
    if type(entry) is _Continuation:
        entry.poisoned = True
        if entry.historical:
            product._poison(connection, entry.owner)
        else:
            from app.maintenance import fresh_product as fresh

            cast(fresh._Entry, entry.owner).poisoned = True


def _prepare(connection, owner, *, historical):
    from app.maintenance import fresh_product as fresh
    from app.maintenance import product_adoption as product

    _require(connection.info.get(_KEY) is None)
    if historical:
        state = product._check(connection, owner, "lab claim lease adopted, final admission pending")
        product._continuity(connection, state)
        _require(not state.lab_claim_unverified and state.checkpoint_transition.final is not None)
        original = state.checkpoint_transition.raw_acks
    else:
        _require(fresh._issued(connection) is owner)
        fresh._check(connection, owner)
        _require(owner.prepared and owner.next_stage == len(fresh._STAGES))
        verified_fresh_packet = _consume_fresh_stages(connection, owner)
        original = ()
    provenance = product._provenance()
    graph = provenance[4][0]
    _require(retained._version_rows(connection) == retained._stage_versions(graph, "a006_lab_claim_lease", final=True))
    root = _connection_preflight(connection)
    args = (
        connection,
        root,
        tokens._physical_context(connection),
        _roles(connection),
        provenance,
        history._oid(connection, "alembic_version"),
        owner,
        historical,
        object(),
        original,
        history._oid(connection, checkpoint._TABLE),
        history._oid(connection, "course_completions", "mod_learning"),
        catalog.observe(connection) if historical else verified_fresh_packet,
    )
    entry = object.__new__(_Continuation)
    _Continuation.__init__(entry, *args)
    connection.info[_KEY] = entry
    _check(connection, entry)
    return entry


def _config(connection, entry):
    cfg = ordinary_migration_config()
    cfg.attributes["connection"] = connection
    _verify_config(connection, entry, cfg)
    return cfg


def _verify_config(connection, entry, cfg):
    from alembic.script import ScriptDirectory

    _require(cfg.attributes.get("connection") is connection)
    expected = ordinary_migration_config()
    scripts = ScriptDirectory.from_config(cfg)
    locations = {Path(p).resolve() for p in expected.attributes["academy_migration_locations"]}
    _require(len(scripts.version_locations) == len(locations) == 3)
    _require({Path(p).resolve() for p in scripts.version_locations} == locations)
    _require(len(cfg.attributes["academy_migration_locations"]) == len(locations))
    _require({Path(p).resolve() for p in cfg.attributes["academy_migration_locations"]} == locations)
    expected_script = expected.get_main_option("script_location")
    _require(type(expected_script) is str)
    _require(Path(scripts.dir).resolve() == Path(cast(str, expected_script)).resolve())
    graph = tuple(sorted((s.revision, s.down_revision, s.dependencies) for s in scripts.walk_revisions()))
    _require((graph, tuple(sorted(scripts.get_heads()))) == entry.provenance[4])


def _run(connection, owner, *, historical):
    entry = None
    guard = None
    try:
        entry = _prepare(connection, owner, historical=historical)

        def forbid_commit(conn):
            _poison(connection, entry)
            _require(False)

        guard = forbid_commit
        sa.event.listen(connection, "commit", guard)
        cfg = _config(connection, entry)
        graph = entry.provenance[4][0]
        for stage in _STAGES:
            _check(connection, entry)
            _require(not entry.consumed and entry.next_stage == _STAGES.index(stage))
            before = catalog.observe(connection)
            _require(before == entry.packet)
            rows = catalog.row_evidence(connection, before)
            grandfathers = catalog.grandfather_keys(connection) if stage == _STAGES[-1] else ()
            _verify_config(connection, entry, cfg)
            command.upgrade(cfg, stage)
            _verify_config(connection, entry, cfg)
            _check(connection, entry)
            _require(cfg.attributes["connection"] is connection)
            _require(retained._version_rows(connection) == retained._stage_versions(graph, stage, final=True))
            after = catalog.observe(connection)
            catalog.validate_stage(
                connection, before, after, stage, original_rows=rows, expected_grandfathers=grandfathers
            )
            _check(connection, entry)
            entry.packet = after
            entry.next_stage += 1
        _verify_config(connection, entry, cfg)
        command.upgrade(cfg, _A011)
        _verify_config(connection, entry, cfg)
        _check(connection, entry)
        _require(entry.consumed and entry.recorded and cfg.attributes["connection"] is connection)
        _require(retained._version_rows(connection) == retained._stage_versions(graph, _A011, final=True))
        _require(catalog.observe(connection) == entry.packet)
        _verify_final_rows(connection, entry)
        _check(connection, entry)
    except BaseException:
        _poison(connection, entry)
        # A failed preparation must poison the already-issued owner too.
        if entry is None:
            from app.maintenance import product_adoption as product

            if historical:
                product._poison(connection, owner)
            else:
                owner.poisoned = True
        raise
    finally:
        if guard is not None:
            sa.event.remove(connection, "commit", guard)
        if type(entry) is _Continuation:
            entry.runner = None
            entry.original_acks = ()
            entry.packet.clear()
            if entry.row_packet is not None:
                entry.row_packet.clear()
            entry.row_packet = None
            entry.row_oracle = None
            connection.info.pop(_KEY, None)


def _consume(connection):
    """a011 consumes the exact issued continuation before the first effect."""
    entry = connection.info.get(_KEY)
    try:
        _check(connection, entry)
        _require(entry.next_stage == len(_STAGES) and not entry.consumed and not entry.recorded)
        entry.consumed = True
        _require(
            retained._version_rows(connection) == retained._stage_versions(entry.provenance[4][0], _A011, final=False)
        )
        _require(catalog.observe(connection) == entry.packet)
        _require(history._oid(connection, catalog._MEMBER) is None)
        _require(
            not history._query(
                connection,
                (
                    "SELECT typname FROM pg_catalog.pg_type WHERE typnamespace='public'::regnamespace AND "
                    "typname=ANY(:names)"
                ),
                names=[catalog._MEMBER, "_" + catalog._MEMBER],
            )
        )
        _require(
            not history._query(
                connection,
                (
                    "SELECT relname FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace "
                    "AND relname=ANY(:names)"
                ),
                names=[catalog._MEMBER, catalog._MEMBER + "_pkey"],
            )
        )
        _require(
            not history._query(
                connection,
                (
                    "SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=:oid AND "
                    "attname='erp_synced_pct' AND NOT attisdropped"
                ),
                oid=entry.checkpoint_oid,
            )
        )
        return entry
    except BaseException:
        _poison(connection, entry)
        raise


def _record(connection, entry, original_rows):
    try:
        _check(connection, entry)
        _require(entry.consumed and not entry.recorded and entry.next_stage == len(_STAGES))
        after = catalog.observe(connection)
        catalog.validate_stage(connection, entry.packet, after, _A011, original_rows=original_rows)
        membership = history._query(
            connection, "SELECT tenant_id,completion_id FROM public.academy_erp_imported_completion_keys ORDER BY 1,2"
        )
        _require(membership == tuple((t, i) for t, i, _ in entry.original_acks))
        _require(
            connection.scalar(
                sa.text(
                    (
                        "SELECT NOT EXISTS (SELECT 1 FROM public.academy_erp_completion_checkpoints WHERE "
                        "erp_synced_pct IS NOT NULL)"
                    )
                )
            )
            is True
        )
        entry.row_packet = entry.packet
        entry.row_oracle = original_rows
        entry.packet = after
        entry.recorded = True
        _check(connection, entry)
    except BaseException:
        _poison(connection, entry)
        raise


def _verify_final_rows(connection, entry):
    """Recheck data AFTER the final Alembic version write and callbacks."""
    _require(entry.recorded and entry.row_packet is not None and entry.row_oracle is not None)
    _require(
        catalog.row_evidence(connection, entry.row_packet, omissions=((checkpoint._TABLE, ("erp_synced_pct",)),))
        == entry.row_oracle
    )
    membership = history._query(
        connection, "SELECT tenant_id,completion_id FROM public.academy_erp_imported_completion_keys ORDER BY 1,2"
    )
    _require(membership == tuple((tenant, identifier) for tenant, identifier, _ in entry.original_acks))
    _require(
        connection.scalar(
            sa.text(
                "SELECT NOT EXISTS (SELECT 1 FROM public.academy_erp_completion_checkpoints "
                "WHERE erp_synced_pct IS NOT NULL)"
            )
        )
        is True
    )


_FRESH_KEY = object()


@dataclass(slots=True, repr=False)
class _FreshStages:
    owner: object
    connection: object
    root: object
    physical: tuple
    roles: tuple
    provenance: tuple
    version_oid: int
    parent_keys: dict
    packet: dict
    observed: int = 0
    consumed: bool = False
    poisoned: bool = False

    def __new__(cls, *args, **kwargs):
        raise RuntimeError("Fresh product stages are privately issued")


def _prepare_fresh_stages(connection, owner):
    """Issued before a004 DDL beneath the genuine fresh preparation boundary."""
    from app.maintenance import fresh_product as fresh
    from app.maintenance import product_adoption as product

    fresh._check(connection, owner)
    _require(fresh._issued(connection) is owner and not owner.prepared and owner.next_stage == 0)
    _require(connection.info.get(_FRESH_KEY) is None)
    provenance = product._provenance()
    _require(owner.graph == provenance[4][0])
    _require(fresh._versions(connection) == fresh._cut(owner.graph, fresh._STAGES[0], final=False))
    parents = {
        (ns, t): retained._key(connection, ns, t, cols, name, kind)
        for ns, t, cols, name, kind in retained._parent_specs(final=True)
        if t not in ("applicants", "lab_instances")
    }
    checkpoint._held(
        connection, {value[0] for value in parents.values()} | {history._oid(connection, "alembic_version")}
    )
    stage = object.__new__(_FreshStages)
    _FreshStages.__init__(
        stage,
        owner,
        connection,
        _connection_preflight(connection),
        tokens._physical_context(connection),
        _roles(connection),
        provenance,
        history._oid(connection, "alembic_version"),
        parents,
        catalog.observe(connection),
    )
    connection.info[_FRESH_KEY] = stage
    return stage


def _check_fresh_stages(connection, owner):
    from app.maintenance import fresh_product as fresh
    from app.maintenance import product_adoption as product

    stage = connection.info.get(_FRESH_KEY)
    _require(type(stage) is _FreshStages and stage.owner is owner and stage.connection is connection)
    fresh._check(connection, owner)
    _require(not stage.poisoned and not stage.consumed)
    _require(_connection_preflight(connection) is stage.root and tokens._physical_context(connection) == stage.physical)
    _require(_roles(connection) == stage.roles and product._provenance() == stage.provenance)
    _require(history._oid(connection, "alembic_version") == stage.version_oid)
    _require(owner.graph == stage.provenance[4][0])
    _require(catalog.observe(connection) == stage.packet)
    return stage


def _run_fresh_stages(connection, owner):
    from app.maintenance import fresh_product as fresh

    stage = None
    try:
        stage = _check_fresh_stages(connection, owner)
        cfg = _config(connection, stage)
        for ordinal, target in enumerate(fresh._STAGES):
            _check_fresh_stages(connection, owner)
            _require(stage.observed == ordinal and owner.next_stage == ordinal)
            _require(fresh._versions(connection) == fresh._cut(owner.graph, target, final=False))
            before = stage.packet
            rows = catalog.row_evidence(connection, before)
            keys = checkpoint._parent_keys(connection) if ordinal else None
            _verify_config(connection, stage, cfg)
            command.upgrade(cfg, target)
            _verify_config(connection, stage, cfg)
            # _apply advanced execution count, never the independent ordinal.
            fresh._check(connection, owner)
            _require(cfg.attributes["connection"] is connection and owner.next_stage == ordinal + 1)
            _require(fresh._versions(connection) == fresh._cut(owner.graph, target, final=True))
            _require(
                _connection_preflight(connection) is stage.root
                and tokens._physical_context(connection) == stage.physical
            )
            _require(_roles(connection) == stage.roles)
            from app.maintenance import product_adoption as product

            _require(product._provenance() == stage.provenance)
            after = catalog.observe(connection)
            catalog.validate_fresh_stage(
                connection,
                before,
                after,
                target,
                original_rows=rows,
                parent_keys=stage.parent_keys,
                checkpoint_keys=keys,
            )
            stage.packet = after
            stage.observed += 1
            _check_fresh_stages(connection, owner)
    except BaseException:
        owner.poisoned = True
        if type(stage) is _FreshStages:
            stage.poisoned = True
        raise


def _consume_fresh_stages(connection, owner):
    from app.maintenance import fresh_product as fresh

    stage = _check_fresh_stages(connection, owner)
    _require(stage.observed == len(fresh._STAGES) and owner.next_stage == stage.observed and owner.prepared)
    _require(fresh._versions(connection) == fresh._cut(owner.graph, fresh._STAGES[-1], final=True))
    stage.consumed = True
    packet = stage.packet
    stage.packet = {}
    connection.info.pop(_FRESH_KEY, None)
    return packet


def _dispose_fresh_stages(connection, owner):
    stage = connection.info.get(_FRESH_KEY)
    if type(stage) is _FreshStages and stage.owner is owner:
        stage.poisoned = True
        stage.parent_keys.clear()
        stage.packet.clear()
        connection.info.pop(_FRESH_KEY, None)
