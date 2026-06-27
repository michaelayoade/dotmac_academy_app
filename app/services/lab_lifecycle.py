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
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.assessment import Activity, Score, Submission
from app.models.lab import LabInstance, LabTemplate
from app.services.checks.engine import run_checks
from app.services.lab_seed import generate_seed, interpolate
from app.services.labengine.interface import LabEngine, LabHandle

_ACTIVE_STATUSES = ("provisioning", "active")

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


def start_console(cname: str, base_path: str) -> int | None:
    """Launch a ttyd browser terminal for a Linux container; return its port.

    ttyd serves an HTTP page + a WebSocket on ``127.0.0.1:<port>``. ``-b`` sets
    the URL base path so ttyd's internal links (index, /token, /ws) resolve under
    the auth-gated app proxy path; ``-W`` makes the terminal writable.

    Tolerant by design: if ttyd is not installed or the launch fails we log and
    return ``None`` so a missing console binary never blocks provisioning.
    """
    if shutil.which("ttyd") is None:
        logger.warning("ttyd not installed; skipping console for %s", cname)
        return None
    port = _free_port()
    argv = [
        "ttyd", "-p", str(port), "-i", "127.0.0.1", "-b", base_path, "-W",
        "docker", "exec", "-it", cname, "sh",
    ]
    try:
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell interpolation
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception as exc:  # never fail provision on a console launch error
        logger.warning("ttyd launch failed for %s: %s", cname, exc)
        return None
    return port


def stop_consoles(instance: LabInstance) -> None:
    """Kill any ttyd processes serving this instance's console base paths."""
    pattern = f"ttyd .* /labs/instances/{instance.id}/console/"
    argv = ["pkill", "-f", pattern]
    try:
        subprocess.run(  # noqa: S603 - fixed argv, no shell interpolation
            argv, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception as exc:
        logger.warning("stop_consoles failed for %s: %s", instance.id, exc)


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


def active_count(db: Session, tenant_id) -> int:
    """Count instances currently consuming capacity (provisioning|active)."""
    return int(
        db.scalar(
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.tenant_id == tenant_id)
            .where(LabInstance.status.in_(_ACTIVE_STATUSES))
        )
        or 0
    )


def instance_name(tenant_id, person_id, activity_id, n) -> str:
    """Stable, human-traceable instance name: ``dal-<t8>-<p8>-<a8>-<n>``."""
    return f"dal-{str(tenant_id)[:8]}-{str(person_id)[:8]}-{str(activity_id)[:8]}-{n}"


def _attempt_seed_id(person_id, activity_id, n: int) -> int:
    """Deterministic 32-bit PRNG seed, stable per (person, activity, attempt)."""
    h = hashlib.sha256(f"{person_id}:{activity_id}:{n}".encode()).hexdigest()
    return int(h[:8], 16)


def request_lab(db: Session, *, tenant_id, person_id, activity: Activity,
                template: LabTemplate) -> LabInstance:
    """Create a LabInstance for the next attempt — does NOT deploy.

    Queued if at/over ``MAX_CONCURRENT_LABS``, else marked ``provisioning`` for
    the worker to pick up. Seed is generated deterministically per attempt.
    """
    prev = db.scalar(
        select(func.count())
        .select_from(LabInstance)
        .where(LabInstance.tenant_id == tenant_id)
        .where(LabInstance.activity_id == activity.id)
        .where(LabInstance.person_id == person_id)
    )
    n = int(prev or 0) + 1
    seed = generate_seed(template.seed_spec, attempt_id=_attempt_seed_id(person_id, activity.id, n))
    at_capacity = active_count(db, tenant_id) >= settings.max_concurrent_labs
    inst = LabInstance(
        tenant_id=tenant_id,
        activity_id=activity.id,
        person_id=person_id,
        instance_name=instance_name(tenant_id, person_id, activity.id, n),
        seed=seed,
        status="queued" if at_capacity else "provisioning",
        consoles={},
    )
    db.add(inst)
    db.flush()
    return inst


def provision(db: Session, instance: LabInstance, engine: LabEngine,
              template: LabTemplate) -> LabInstance:
    """Deploy the topology for ``instance`` and record consoles / activate it."""
    try:
        topology_text = _set_topology_name(
            interpolate(template.topology, instance.seed), instance.instance_name
        )
        handle = engine.deploy(topology_text, instance.instance_name)
        consoles: dict = {}
        for node in handle.nodes:
            kind = handle.kinds.get(node)
            spec = {"kind": kind, "mgmt": handle.mgmt.get(node)}
            if _is_linux_kind(kind):
                spec["port"] = start_console(
                    handle.nodes[node],
                    f"/labs/instances/{instance.id}/console/{node}",
                )
            consoles[node] = spec
        instance.consoles = consoles
        instance.status = "active"
        now = _now()
        instance.started_at = now
        instance.last_active_at = now
        instance.error = None
    except Exception as exc:  # surface any deploy failure onto the row
        instance.status = "error"
        instance.error = str(exc)
    db.flush()
    return instance


def grade(db: Session, instance: LabInstance, engine: LabEngine,
          template: LabTemplate, handle: LabHandle) -> Score:
    """Run the template checks against the live instance and write Submission+Score.

    The caller supplies ``handle`` (the live :class:`LabHandle` — see the web/CLI
    callers which reconstruct it via the engine); this keeps grade pure and
    testable. Mirrors ``submit_activity``: ``attempt_no`` = max+1, flush, no commit.
    """
    result = run_checks(template.checks, engine, handle, instance.seed)
    score_val = result["score"]
    max_score = result["max_score"]
    fraction = (score_val / max_score) if max_score else 0.0

    threshold = template.limits.get("pass_threshold")
    if threshold is None:
        act = db.scalars(
            select(Activity)
            .where(Activity.tenant_id == instance.tenant_id)
            .where(Activity.id == instance.activity_id)
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
        attempt_no=int(prev) + 1,
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
    # Auto-on-pass notification — best effort, must never break grading.
    try:
        from app.models.person import Person
        from app.services.email import notify_score_if_first_pass

        act = db.scalars(
            select(Activity)
            .where(Activity.tenant_id == instance.tenant_id)
            .where(Activity.id == instance.activity_id)
        ).first()
        person = db.get(Person, instance.person_id)
        if act is not None:
            notify_score_if_first_pass(db, score=score, activity=act, person=person)
    except Exception as exc:  # noqa: BLE001 - grading must succeed regardless
        logger.warning("auto-on-pass notification failed: %s", exc)
    return score


def reset(db: Session, instance: LabInstance, engine: LabEngine,
          template: LabTemplate) -> LabInstance:
    """Tear down and redeploy the instance topology in place (fresh state)."""
    engine.reset(interpolate(template.topology, instance.seed), instance.instance_name)
    instance.last_active_at = _now()
    db.flush()
    return instance


def destroy(db: Session, instance: LabInstance, engine: LabEngine) -> LabInstance:
    """Destroy the underlying lab and mark the instance ``reaped``."""
    stop_consoles(instance)
    engine.destroy(instance.instance_name)
    instance.status = "reaped"
    db.flush()
    return instance
