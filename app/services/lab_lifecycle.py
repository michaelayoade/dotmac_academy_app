"""Lab lifecycle service (Task 6): quota-gated request, provision, grade→ledger.

Mirrors ``app/services/assessment.submit_activity`` for the grade path: it
builds a ``Submission`` + ``Score`` directly (no MCQ grader) from the check
engine result so lab attempts flow into the same Score/ledger spine.

Inc1 rule: these functions take ``db`` and ``flush`` only — they NEVER
``commit``. The request handler / CLI owns the transaction boundary.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.assessment import Activity, Score, Submission
from app.models.lab import LabInstance, LabTemplate
from app.services.checks.engine import run_checks
from app.services.exceptions import ConflictError
from app.services.host_lock import HostLockUnavailable
from app.services.lab_seed import generate_seed, interpolate
from app.services.labengine.interface import LabEngine, LabHandle

#: URL prefix under which every console is served. Defined once: it is both the
#: ttyd ``-b`` base path and the pattern the orphan sweep matches on.
_CONSOLE_BASE = "/labs/instances/"

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _free_port() -> int:
    """Pick an ephemeral free localhost port (race-tolerant best effort)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _is_linux_kind(kind) -> bool:
    """Linux lab nodes get a ttyd terminal; RouterOS (vr-*) use webfig instead."""
    return not str(kind or "").startswith("vr")


def console_bind_host() -> str:
    """Address a locally spawned ttyd binds — see ``LAB_CONSOLE_BIND_HOST``."""
    return settings.lab_console_bind_host or settings.lab_console_host


def _is_local_address(host: str) -> bool:
    """True when this host owns ``host`` and ttyd could actually bind it.

    ttyd (libwebsockets) does NOT exit when its ``-i`` address is not local: it
    retries the bind in a tight loop, burning a whole core and never listening.
    Probing the bind ourselves turns that silent runaway into a refusal we log.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
        return True
    except OSError:
        return False


def start_console(cname: str, base_path: str) -> int | None:
    """Launch a ttyd browser terminal for a Linux container; return its port.

    ttyd serves an HTTP page + a WebSocket on ``<bind host>:<port>``. ``-b`` sets
    the URL base path so ttyd's internal links (index, /token, /ws) resolve under
    the auth-gated app proxy path; ``-W`` makes the terminal writable.

    Tolerant by design: if ttyd is missing, the bind address is not local, or the
    launch fails we log and return ``None`` so a console problem never blocks
    provisioning.

    Known, pre-existing limitation (not introduced or changed by the worker
    process-containment/singleton-lock work — confirmed by checking this
    unit's own history: no explicit ``KillMode`` was ever set before that
    work, so systemd's own default, which is already ``control-group``, was
    already in effect): ttyd is spawned as an ordinary child of the worker
    process, in the worker's own cgroup. Any worker stop/restart (a crash
    triggering ``Restart=always``, a manual ``systemctl restart``, or a
    deploy) therefore kills every running console too, while
    ``LabInstance.consoles`` in the database keeps advertising the now-dead
    port. `lab_jobs.sweep_orphan_consoles` only ever *deletes* stale console
    entries for instances that are no longer live-counted for capacity — it
    has no path that *detects* a still-active instance's console has died
    and recreates it. A learner's browser console for any active Linux lab
    is silently broken until that instance is reset or redeployed. Tracked
    as an explicit follow-up (see Knowledge slug
    ``academy-lab-worker-console-restart-fragility``), not fixed here.
    """
    if shutil.which("ttyd") is None:
        logger.warning("ttyd not installed; skipping console for %s", cname)
        return None
    bind_host = console_bind_host()
    if not _is_local_address(bind_host):
        # Refusing is the whole point: spawning here would leak a process that
        # spins on an impossible bind until someone kills it by hand.
        logger.error(
            "console bind host %s is not local to this machine; refusing to spawn "
            "ttyd for %s (set LAB_CONSOLE_BIND_HOST, or run the lab worker on the "
            "host that owns that address)",
            bind_host,
            cname,
        )
        return None
    port = _free_port()
    argv = [
        "ttyd",
        "-p",
        str(port),
        "-i",
        bind_host,
        "-b",
        base_path,
        "-W",
        "docker",
        "exec",
        "-it",
        cname,
        "sh",
    ]
    try:
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:  # never fail provision on a console launch error
        logger.warning("ttyd launch failed for %s: %s", cname, exc)
        return None
    return port


def console_pids(instance_id=None) -> dict[str, list[int]]:
    """Map instance id -> PIDs of the ttyd consoles currently serving it.

    Reads the process table via ``pgrep -af`` and parses the ``-b`` base path,
    which carries the instance id. Passing ``instance_id`` narrows the scan to
    one instance. Returns ``{}`` when nothing matches or ``pgrep`` is absent.
    """
    scope = str(instance_id) if instance_id is not None else r"[0-9a-f-]+"
    pattern = rf"ttyd .* -b {_CONSOLE_BASE}{scope}/console/"
    try:
        proc = subprocess.run(
            ["pgrep", "-af", pattern], check=False, capture_output=True, text=True
        )
    except Exception as exc:
        logger.warning("console_pids scan failed: %s", exc)
        return {}
    found: dict[str, list[int]] = {}
    for line in proc.stdout.splitlines():
        pid_text, _, cmdline = line.partition(" ")
        match = re.search(rf"-b {_CONSOLE_BASE}([0-9a-f-]+)/console/", cmdline)
        if match is None or not pid_text.isdigit():
            continue
        found.setdefault(match.group(1), []).append(int(pid_text))
    return found


def stop_consoles(instance: LabInstance) -> int:
    """Kill the ttyd processes serving this instance's consoles; return the count.

    Returns a count rather than ``None`` so callers (and the orphan sweep) can log
    what actually happened — a silent no-op here is how consoles leaked before.
    """
    return kill_consoles(
        pid for pids in console_pids(instance.id).values() for pid in pids
    )


def kill_consoles(pids) -> int:
    """SIGTERM each console PID, tolerating one that already exited."""
    killed = 0
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            killed += 1
        except ProcessLookupError:
            continue  # already gone — nothing to do
        except OSError as exc:
            logger.warning("could not kill console pid %s: %s", pid, exc)
    return killed


def _set_topology_name(topology_text: str, name: str) -> str:
    """Force the containerlab topology ``name:`` to the unique per-trainee
    instance name, so concurrent deployments never collide and the container
    names (``clab-<name>-<node>``) match ``handle_for``."""
    if re.search(r"(?m)^\s*name:\s*.*$", topology_text):
        return re.sub(r"(?m)^\s*name:\s*.*$", f"name: {name}", topology_text, count=1)
    return f"name: {name}\n{topology_text}"


def handle_for(instance: LabInstance) -> LabHandle:
    """Reconstruct a :class:`LabHandle` from a live instance's recorded consoles.

    ``provision`` persists ``consoles[node] = {"kind", "mgmt"}``; container names
    follow containerlab's ``clab-<instance>-<node>`` convention, so we can rebuild
    the handle without re-inspecting the engine (used by the grade/check path).
    """
    consoles = instance.consoles or {}
    return LabHandle(
        instance_name=instance.instance_name,
        nodes={node: f"clab-{instance.instance_name}-{node}" for node in consoles},
        mgmt={node: c.get("mgmt") for node, c in consoles.items()},
        kinds={node: c.get("kind") for node, c in consoles.items()},
    )


def instance_name(instance_id) -> str:
    """Runtime name: ``dal-<canonical-hyphenated-uuid>``.

    The instance's own id is the whole name — global uniqueness follows
    directly from ``id`` being a UUID, backed by the DB-level unique index on
    ``instance_name`` (defense in depth: containerlab's runtime namespace is
    host-global, not tenant-scoped, so a tenant-scoped uniqueness guarantee on
    ``id`` alone would not be sufficient for the runtime name it derives).
    """
    return f"dal-{instance_id}"


def _attempt_seed_id(person_id, activity_id, n: int) -> int:
    """Deterministic 32-bit PRNG seed, stable per (person, activity, attempt)."""
    h = hashlib.sha256(f"{person_id}:{activity_id}:{n}".encode()).hexdigest()
    return int(h[:8], 16)


def _launch_lock_key(tenant_id, person_id, activity_id) -> int:
    """Stable signed bigint key for one learner/activity launch stream."""
    digest = hashlib.sha256(
        f"lab-launch:{tenant_id}:{person_id}:{activity_id}".encode()
    ).digest()
    unsigned = int.from_bytes(digest[:8], "big")
    return unsigned if unsigned < (1 << 63) else unsigned - (1 << 64)


def request_lab(db: Session, *, tenant_id, person_id, activity: Activity, template: LabTemplate) -> LabInstance:
    """Create a LabInstance for the next attempt — does NOT deploy.

    Always queued for the worker-owned admission path. Concurrent or retried
    launches for the same learner/activity serialize and reuse the current
    non-reaped instance. Seed generation, instance creation, and the deploy
    intent otherwise occur atomically in the same request transaction.
    """
    db.execute(
        select(
            func.pg_advisory_xact_lock(
                _launch_lock_key(tenant_id, person_id, activity.id)
            )
        )
    )
    current = db.scalars(
        select(LabInstance)
        .where(LabInstance.tenant_id == tenant_id)
        .where(LabInstance.activity_id == activity.id)
        .where(LabInstance.person_id == person_id)
        .where(LabInstance.status != "reaped")
        .order_by(LabInstance.created_at.desc())
    ).first()
    if current is not None:
        return current

    prev = db.scalar(
        select(func.count())
        .select_from(LabInstance)
        .where(LabInstance.tenant_id == tenant_id)
        .where(LabInstance.activity_id == activity.id)
        .where(LabInstance.person_id == person_id)
    )
    n = int(prev or 0) + 1
    seed = generate_seed(template.seed_spec, attempt_id=_attempt_seed_id(person_id, activity.id, n))
    # Allocated explicitly (rather than left to uuid_pk()'s column default)
    # because the runtime name is derived from it below, before the row is
    # ever flushed — SQLAlchemy applies column defaults at INSERT/flush time,
    # not at ordinary Python object construction, so instance.id would still
    # be None here if read off the LabInstance() object instead.
    instance_id = uuid4()
    inst = LabInstance(
        id=instance_id,
        tenant_id=tenant_id,
        activity_id=activity.id,
        person_id=person_id,
        instance_name=instance_name(instance_id),
        seed=seed,
    )
    db.add(inst)
    db.flush()
    from app.services.lab_operations import enqueue

    enqueue(db, instance=inst, kind="deploy", requested_by=person_id)
    from app.services import learning_events

    learning_events.emit(
        db, tenant_id=tenant_id, person_id=person_id, kind="lab_launched",
        course_id=activity.course_id, subject_id=activity.id,
        detail={"instance": str(inst.id)},
    )
    return inst


def provision(db: Session, instance: LabInstance, engine: LabEngine, template: LabTemplate) -> LabInstance:
    """Deploy the topology for ``instance`` and record consoles / activate it.

    A failure BEFORE ``engine.deploy()`` is ever invoked (topology
    interpolation, name substitution) proves no runtime was created, so it is
    recorded as ``error``. A failure AT OR AFTER the ``engine.deploy()`` call
    does not prove the runtime is absent — the underlying containerlab
    process may still be running in the background — so the instance
    conservatively stays ``active`` instead, mirroring ``_run_deploy``'s
    destroy-failure handling in ``lab_operations.py``. Capacity accounting
    (``_capacity_available``) is presence-based, not status-based: this
    failure path sets ``instance.runtime_presence = "unknown"`` (set the
    moment invocation is reached, see below), which keeps it capacity-counted
    exactly like a genuinely active instance would be, and over-counting a
    phantom-but-live instance self-heals via ``reconcile_runtime`` once
    inventory proves absence, whereas under-counting would not self-correct
    as safely. ``instance.error`` is set to a non-``None`` message on every
    failure path — callers (``_run_deploy``) key off it, not just ``status``,
    to detect a failed deploy now that a failure can leave ``status ==
    "active"``. ``HostLockUnavailable`` is transient host-lock contention, not
    a deployment failure, and is re-raised unchanged rather than recorded here.
    """
    try:
        topology_text = _set_topology_name(interpolate(template.topology, instance.seed), instance.instance_name)
    except Exception as exc:  # nothing was ever attempted; no runtime to protect
        instance.status = "error"
        instance.error = str(exc)
        instance.runtime_presence = "absent"
        db.flush()
        return instance

    # Set immediately before invocation — an exception at or after this point
    # does not prove the runtime is absent.
    instance.runtime_presence = "unknown"
    try:
        handle = engine.deploy(topology_text, instance.instance_name)
        consoles: dict = {}
        for node in handle.nodes:
            kind = handle.kinds.get(node)
            spec = {"kind": kind, "mgmt": handle.mgmt.get(node)}
            if _is_linux_kind(kind):
                spec["port"] = start_console(
                    handle.nodes[node],
                    f"{_CONSOLE_BASE}{instance.id}/console/{node}",
                )
            consoles[node] = spec
        instance.consoles = consoles
        instance.status = "active"
        now = _now()
        instance.started_at = now
        instance.last_active_at = now
        instance.error = None
        instance.runtime_presence = "present"
    except HostLockUnavailable:
        raise
    except Exception as exc:  # deploy was invoked; failure doesn't prove absence
        instance.status = "active"
        instance.error = str(exc)
        instance.runtime_presence = "unknown"
    db.flush()
    return instance


def provision_if_absent(
    db: Session,
    instance: LabInstance,
    engine: LabEngine,
    template: LabTemplate,
    *,
    preserved_status: str,
    preserved_error: str | None,
) -> LabInstance:
    """Conditional deploy for a reconciler-originated "runtime_repair" intent.

    LOAD-BEARING ORDERING (see migration ``0060_lab_conditional_ops.py``'s
    module docstring for the full design rationale — an earlier, unauthorized
    attempt at this exact slice got this ordering wrong):

        locked precondition check
        -> conditional containerlab mutation, IF the precondition allows it
        -> console teardown, ONLY IF a mutation actually occurred
        -> console recreation / final state projection

    ``engine.deploy_if_absent()`` performs the precondition check AND the
    mutation atomically inside one host-lock acquisition (see
    ``ContainerlabEngine.deploy_if_absent``) — this function never calls
    ``stop_consoles``/``start_console``/any topology mutation before that
    call has already returned a real handle proving the mutation occurred.

    A precondition MISMATCH (``deploy_if_absent`` returns ``None`` — the
    runtime was found genuinely present, whether by this call's own
    authoritative check or a caller's own earlier preliminary check racing
    against it) is the no-op path: ``status``/``error`` are restored to
    ``preserved_status``/``preserved_error`` (the instance's values from
    immediately before the caller's capacity-admission reservation
    overwrote them with a "resetting"/"provisioning" placeholder — see
    ``app/services/lab_operations.py``'s conditional-deploy branch), and only
    ``runtime_presence`` is refreshed to ``"present"`` from this genuine,
    fresh observation. ``consoles`` is untouched throughout — nothing above
    this call ever writes it. No call to ``stop_consoles``, ``engine.deploy``,
    or any topology/filesystem mutation happens on this path.
    """
    topology_text = _set_topology_name(
        interpolate(template.topology, instance.seed), instance.instance_name
    )
    # Set immediately before invocation, mirroring provision()'s own
    # reasoning: an exception at or after this point does not prove the
    # runtime is absent.
    instance.runtime_presence = "unknown"
    handle = engine.deploy_if_absent(topology_text, instance.instance_name)
    if handle is None:
        # Precondition mismatch — runtime is genuinely present. NOTHING was
        # mutated: restore status/error to their pre-admission values and
        # only refresh presence from this fresh observation.
        instance.status = preserved_status
        instance.error = preserved_error
        instance.runtime_presence = "present"
        db.flush()
        return instance
    # Precondition held (genuinely absent) and deploy_if_absent has already
    # performed the real mutation atomically — console teardown/recreation
    # may only run now, after that mutation is proven to have happened.
    stop_consoles(instance)
    consoles: dict = {}
    for node in handle.nodes:
        kind = handle.kinds.get(node)
        spec = {"kind": kind, "mgmt": handle.mgmt.get(node)}
        if _is_linux_kind(kind):
            spec["port"] = start_console(
                handle.nodes[node],
                f"{_CONSOLE_BASE}{instance.id}/console/{node}",
            )
        consoles[node] = spec
    instance.consoles = consoles
    instance.status = "active"
    now = _now()
    instance.started_at = now
    instance.last_active_at = now
    instance.error = None
    instance.runtime_presence = "present"
    db.flush()
    return instance


def destroy_if_present(db: Session, instance: LabInstance, engine: LabEngine) -> LabInstance:
    """Conditional destroy for a reconciler-originated "runtime_cleanup" intent.

    Mirrors :func:`provision_if_absent`'s load-bearing ordering exactly:
    locked precondition check -> conditional mutation (only if present) ->
    console teardown (only if a mutation actually occurred) -> final
    projection. ``engine.destroy_if_present()`` performs the precondition
    check and the mutation atomically inside one host-lock acquisition.

    A precondition MISMATCH (``destroy_if_present`` returns ``False`` — the
    runtime was found genuinely absent already) is the no-op path:
    ``status``/``error``/``consoles`` are left completely untouched, and only
    ``runtime_presence`` is refreshed to ``"absent"`` from this genuine
    observation. No call to ``stop_consoles`` or any other mutation happens
    on this path.
    """
    destroyed = engine.destroy_if_present(instance.instance_name)
    if not destroyed:
        instance.runtime_presence = "absent"
        db.flush()
        return instance
    stop_consoles(instance)
    instance.status = "reaped"
    instance.runtime_presence = "absent"
    db.flush()
    return instance


def grade(
    db: Session,
    instance: LabInstance,
    engine: LabEngine,
    template: LabTemplate,
    handle: LabHandle,
    *,
    before_each_check: Callable[[], None] | None = None,
) -> Score:
    """Run the template checks against the live instance and write Submission+Score.

    The caller supplies ``handle`` (the live :class:`LabHandle` — see the web/CLI
    callers which reconstruct it via the engine); this keeps grade pure and
    testable. Mirrors ``submit_activity``: ``attempt_no`` = max+1, flush, no commit.
    """
    if instance.status != "active" or instance.error is not None:
        detail = (
            f"status {instance.status!r}"
            if instance.status != "active"
            else "an unresolved infrastructure error"
        )
        raise ConflictError(f"cannot check a lab instance with {detail}")
    result = run_checks(
        template.checks,
        engine,
        handle,
        instance.seed,
        before_each=before_each_check,
    )
    score_val = result["score"]
    max_score = result["max_score"]
    fraction = (score_val / max_score) if max_score else 0.0

    threshold = template.limits.get("pass_threshold")
    if threshold is None:
        act = db.scalars(
            select(Activity).where(Activity.tenant_id == instance.tenant_id).where(Activity.id == instance.activity_id)
        ).first()
        threshold = act.pass_threshold if act is not None else 0.0

    prev = db.scalar(
        select(func.coalesce(func.max(Submission.attempt_no), 0))
        .where(Submission.tenant_id == instance.tenant_id)
        .where(Submission.activity_id == instance.activity_id)
        .where(Submission.person_id == instance.person_id)
    )
    sub = Submission(
        tenant_id=instance.tenant_id,
        activity_id=instance.activity_id,
        person_id=instance.person_id,
        answers={"seed": instance.seed, "instance": str(instance.id)},
        attempt_no=int(prev or 0) + 1,
    )
    db.add(sub)
    db.flush()

    score = Score(
        tenant_id=instance.tenant_id,
        submission_id=sub.id,
        score=score_val,
        max_score=max_score,
        fraction=fraction,
        passed=(max_score > 0 and fraction >= threshold),
        per_item=result["per_check"],
        source="auto",
    )
    db.add(score)
    instance.last_active_at = _now()
    db.flush()
    from app.services import learning_events

    _course_id = None
    _act_for_event = db.scalars(
        select(Activity).where(Activity.tenant_id == instance.tenant_id).where(Activity.id == instance.activity_id)
    ).first()
    if _act_for_event is not None:
        _course_id = _act_for_event.course_id
    learning_events.emit(
        db, tenant_id=instance.tenant_id, person_id=instance.person_id,
        kind="submission_made", course_id=_course_id, subject_id=sub.id,
        detail={"activity_id": str(instance.activity_id), "lab": True,
                "attempt_no": sub.attempt_no},
    )
    learning_events.emit(
        db, tenant_id=instance.tenant_id, person_id=instance.person_id,
        kind="work_graded", course_id=_course_id, subject_id=sub.id,
        detail={"activity_id": str(instance.activity_id), "lab": True,
                "passed": score.passed, "fraction": float(fraction)},
    )
    learning_events.emit(
        db, tenant_id=instance.tenant_id, person_id=instance.person_id,
        kind="lab_check_passed" if score.passed else "lab_check_failed",
        course_id=_course_id, subject_id=instance.activity_id,
        detail={"instance": str(instance.id),
                "checks": len(result.get("per_check") or [])},
    )
    # Auto-on-pass notification — best effort, must never break grading.
    try:
        from app.models.person import Person
        from app.services.email import notify_score_if_first_pass

        act = db.scalars(
            select(Activity).where(Activity.tenant_id == instance.tenant_id).where(Activity.id == instance.activity_id)
        ).first()
        person = db.get(Person, instance.person_id)
        if act is not None:
            notify_score_if_first_pass(db, score=score, activity=act, person=person)
    except Exception as exc:
        logger.warning("auto-on-pass notification failed: %s", exc)
    return score


def reset(db: Session, instance: LabInstance, engine: LabEngine, template: LabTemplate) -> LabInstance:
    """Legacy direct reset helper retained until the separately gated removal phase.

    Web routes never call this helper: they enqueue a durable deploy operation,
    and the lab worker owns destroy-then-deploy, capacity admission, leases,
    and settlement. This guard still keeps any direct service caller from
    bypassing those boundaries while the compatibility helper remains.

    Only ``active`` or ``error`` (a previously-failed deploy, retryable) may
    be reset; every other status is refused up front, before any engine
    interaction. This is an allow-list, not just a reaped exclusion:
    ``queued``/``provisioning`` are the capacity-controlled deployment path
    owned by ``lab_operations.run_claimed()`` (which enforces the effective
    capacity limit before calling ``provision()``) — resetting a ``queued`` instance would
    deploy it immediately and bypass that cap entirely, and resetting a
    ``provisioning`` one would race the worker's own ``provision()`` call on
    the same row/work directory. ``reaped`` (already-destroyed) is refused
    because a successful reset unconditionally sets ``status="active"``,
    which would resurrect it. This guard lives here — not in the web route —
    so it applies to every current and future caller of ``reset()``, not just
    the one route that exists today.

    Mirrors ``provision``'s guarded-deploy shape and its topology preparation:
    ``_set_topology_name()`` is applied the same way so the redeployed
    container names still follow the ``clab-<instance>-<node>`` convention
    ``handle_for`` expects — a reset that skipped this could deploy under the
    wrong name and silently desync from every other reader of ``consoles``.
    An engine/interpolation failure is recorded onto the row
    (``status="error"``) rather than propagating out as an unhandled
    exception — a legacy direct caller gets a normal return in either outcome.
    Only the ``db.flush()`` itself is left
    unguarded, since a database/transaction failure is not something this
    function can meaningfully paper over.

    Old ttyd consoles are stopped BEFORE the fresh ones are started —
    mirroring ``destroy()``'s ordering — because ``stop_consoles()`` matches
    processes by ``instance.id`` alone (see ``console_pids()``), not by the
    specific port each one was launched on. Calling it after starting the new
    consoles would kill the ones just spawned for the same instance, since
    they're indistinguishable from the old ones by that pattern.

    On success, ``instance.consoles`` is rebuilt from the fresh
    :class:`LabHandle` ``engine.reset()`` returns (mgmt IPs and console ports
    can change on redeploy) — the same node/console-spawn loop ``provision``
    uses, so a "successful" reset never leaves stale console/mgmt data on the
    row.
    """
    if instance.status not in ("active", "error"):
        raise ConflictError(f"cannot reset a lab instance with status {instance.status!r}")
    try:
        stop_consoles(instance)
        topology_text = _set_topology_name(interpolate(template.topology, instance.seed), instance.instance_name)
        # Set immediately before invocation — an interpolation/console
        # failure above this line leaves the prior presence value untouched;
        # a failure at or after this line has already crossed into "unknown".
        instance.runtime_presence = "unknown"
        handle = engine.reset(topology_text, instance.instance_name)
        consoles: dict = {}
        for node in handle.nodes:
            kind = handle.kinds.get(node)
            spec = {"kind": kind, "mgmt": handle.mgmt.get(node)}
            if _is_linux_kind(kind):
                spec["port"] = start_console(
                    handle.nodes[node],
                    f"{_CONSOLE_BASE}{instance.id}/console/{node}",
                )
            consoles[node] = spec
        instance.consoles = consoles
        instance.status = "active"
        instance.last_active_at = _now()
        instance.error = None
        instance.runtime_presence = "present"
    except Exception as exc:  # surface any deploy failure onto the row
        instance.status = "error"
        instance.error = str(exc)
        # No presence assignment here: if engine.reset() was never invoked,
        # presence is untouched (still whatever it was before this call); if
        # invocation began, it is already "unknown" from the pre-invocation
        # assignment above.
    db.flush()
    return instance


def destroy(db: Session, instance: LabInstance, engine: LabEngine) -> LabInstance:
    """Destroy the underlying lab and mark the instance ``reaped``.

    A failure here (``engine.destroy`` raising) cannot prove the runtime is
    absent — but this function does not catch it: the outer ``run_claimed``
    caller in ``app/services/lab_operations.py`` already owns settling
    failures for this operation and reapplies ``unknown`` after its own
    rollback, so there is nothing to handle here beyond conservatively
    setting "unknown" before invocation.
    """
    # Set conservatively before invocation, mirroring provision()/reset().
    instance.runtime_presence = "unknown"
    engine.destroy(instance.instance_name)
    stop_consoles(instance)
    instance.status = "reaped"
    instance.runtime_presence = "absent"
    db.flush()
    return instance
