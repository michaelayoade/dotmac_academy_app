"""TDD tests for the lab lifecycle service (Task 6): quota + grade-to-ledger."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.assessment import Activity, Submission
from app.models.course import Course
from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.models.person import Person
from app.services import lab_lifecycle, lab_operations
from app.services.exceptions import ConflictError
from app.services.host_lock import HostLockUnavailable
from app.services.labengine.interface import ExecResult, LabHandle

# The autouse ``_no_real_console_spawn`` fixture in tests/conftest.py replaces
# ``lab_lifecycle.start_console`` for every test, so nothing can leak a real ttyd.
# The few tests that exercise start_console ITSELF need the genuine article —
# captured here at import time, which runs before any fixture. They stub
# ``subprocess.Popen``, so they still spawn nothing.
_REAL_START_CONSOLE = lab_lifecycle.start_console


def _seed(db, tid):
    c = Course(tenant_id=tid, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    db.add(c)
    db.flush()
    act = Activity(tenant_id=tid, course_id=c.id, chapter_number=14, type="lab",
                   title="VLAN Lab", pass_threshold=0.6)
    db.add(act)
    db.flush()
    lt = LabTemplate(
        tenant_id=tid, course_id=c.id, chapter_number=14, activity_id=act.id,
        slug="vlan", title="VLAN", topology="name: x {{o}}",
        instructions_html="<p>do</p>",
        checks=[{"id": "c1", "type": "probe", "node": "client",
                 "probe": {"kind": "ping", "target": "10.0.0.1", "count": 1}}],
        seed_spec={"o": {"type": "int", "min": 2, "max": 9}},
        limits={"time_minutes": 45},
    )
    db.add(lt)
    db.flush()
    p = Person(tenant_id=tid, email="trainee@example.com", first_name="T", last_name="U")
    db.add(p)
    db.flush()
    return c, act, lt, p


def test_instance_name_format(tenant_a):
    instance_id = uuid4()
    name = lab_lifecycle.instance_name(instance_id)
    assert name == f"dal-{instance_id}"


def test_request_lab_names_the_instance_after_its_own_id(admin_session, tenant_a):
    """The new naming scheme: the runtime name IS the instance id, not a
    tenant/person/activity-derived, count-based sequence number."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                     person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    assert inst.instance_name == f"dal-{inst.id}"
    admin_session.rollback()


def test_request_lab_gives_distinct_instances_distinct_uuids_and_names(
    admin_session, tenant_a
):
    """A second request for the same person/activity, after the first
    instance is reaped (so it's no longer the 'current' active/in-flight
    row), must create a brand-new row with its own distinct id/name."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    first = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                      person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    first.status = "reaped"
    admin_session.flush()

    second = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                       person_id=p.id, activity=act, template=lt)
    admin_session.flush()

    assert second.id != first.id
    assert second.instance_name != first.instance_name
    assert second.instance_name == f"dal-{second.id}"
    admin_session.rollback()


def test_request_lab_after_a_hard_delete_does_not_reuse_the_freed_slot(
    admin_session, tenant_a
):
    """The old COUNT(*)-based scheme could theoretically reuse a freed
    sequence number if a row were ever hard-deleted. Nothing in the app does
    this today, but this proves the new UUID-derived scheme doesn't have that
    problem even if something bypassed the app and deleted a row directly."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    first = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                      person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    first_id = first.id
    first_name = first.instance_name

    # Bypass the app entirely — hard-delete the row directly, the way nothing
    # else in this codebase does today.
    admin_session.delete(first)
    admin_session.flush()

    second = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                       person_id=p.id, activity=act, template=lt)
    admin_session.flush()

    assert second.id != first_id
    assert second.instance_name != first_name
    admin_session.rollback()


def test_duplicate_instance_name_is_rejected_at_the_database(
    admin_session, tenant_a, tenant_b
):
    """`uq_lab_instances_instance_name` is a global (not tenant-scoped) unique
    index — containerlab's runtime namespace is host-global, so even two rows
    in different tenants must not share a name."""
    _c_a, act_a, _lt_a, p_a = _seed(admin_session, tenant_a.id)
    _c_b, act_b, _lt_b, p_b = _seed(admin_session, tenant_b.id)
    shared_name = f"dal-{uuid4()}"
    first = LabInstance(tenant_id=tenant_a.id, activity_id=act_a.id, person_id=p_a.id,
                        instance_name=shared_name, seed={})
    admin_session.add(first)
    admin_session.flush()

    second = LabInstance(tenant_id=tenant_b.id, activity_id=act_b.id, person_id=p_b.id,
                         instance_name=shared_name, seed={})
    admin_session.add(second)
    with pytest.raises(IntegrityError) as excinfo:
        admin_session.flush()
    assert "uq_lab_instances_instance_name" in str(excinfo.value)
    admin_session.rollback()


def test_request_lab_queues_when_full(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    monkeypatch.setattr(settings, "max_concurrent_labs", 0)
    inst = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                     person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    assert inst.status == "queued"
    assert inst.instance_name.startswith("dal-")
    assert inst.seed  # seed populated from seed_spec
    admin_session.rollback()


def test_request_lab_always_queues_worker_owned_deploy(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    monkeypatch.setattr(settings, "max_concurrent_labs", 20)
    inst = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                     person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    assert inst.status == "queued"
    operation = admin_session.query(LabOperation).filter_by(instance_id=inst.id).one()
    assert operation.kind == "deploy"
    assert operation.requested_by == p.id
    admin_session.rollback()


def test_concurrent_launches_reuse_one_instance(
    admin_engine, admin_session, tenant_a
):
    _course, activity, template, person = _seed(admin_session, tenant_a.id)
    activity_id = activity.id
    template_id = template.id
    person_id = person.id
    tenant_id = tenant_a.id
    admin_session.commit()
    start = Barrier(2)
    factory = sessionmaker(bind=admin_engine)

    def _launch() -> object:
        db = factory()
        try:
            local_activity = db.get(Activity, activity_id)
            local_template = db.get(LabTemplate, template_id)
            assert local_activity is not None
            assert local_template is not None
            start.wait(timeout=5)
            instance = lab_lifecycle.request_lab(
                db,
                tenant_id=tenant_id,
                person_id=person_id,
                activity=local_activity,
                template=local_template,
            )
            instance_id = instance.id
            db.commit()
            return instance_id
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        instance_ids = list(pool.map(lambda _: _launch(), range(2)))

    assert instance_ids[0] == instance_ids[1]
    assert (
        admin_session.query(LabInstance)
        .filter_by(
            tenant_id=tenant_id,
            person_id=person_id,
            activity_id=activity_id,
        )
        .count()
        == 1
    )


def test_provision_sets_consoles_and_active(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-test2", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name="dal-test2", nodes={"client": "clab-x-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"
    assert out.consoles["client"]["mgmt"] == "172.20.20.3"
    assert out.consoles["client"]["kind"] == "linux"
    assert out.started_at is not None
    engine.deploy.assert_called_once()
    admin_session.rollback()


def test_provision_starts_console_for_linux_node(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-ttyd", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()

    calls = []

    def _fake_start_console(cname, base_path):
        calls.append((cname, base_path))
        return 7321

    monkeypatch.setattr(lab_lifecycle, "start_console", _fake_start_console)
    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name="dal-ttyd",
        nodes={"client": "clab-x-client", "r1": "clab-x-r1"},
        mgmt={"client": "172.20.20.3", "r1": "172.20.20.2"},
        kinds={"client": "linux", "r1": "vr-ros"})
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    # Linux node gets a ttyd port; RouterOS (vr-*) does not (webfig instead).
    assert out.consoles["client"]["port"] == 7321
    assert "port" not in out.consoles["r1"]
    assert calls == [
        ("clab-x-client", f"/labs/instances/{inst.id}/console/client"),
    ]
    admin_session.rollback()


def test_destroy_stops_consoles(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-stop", seed={"o": 5}, status="active", consoles={})
    admin_session.add(inst)
    admin_session.flush()

    stopped = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: stopped.append(i.id))
    engine = MagicMock()
    out = lab_lifecycle.destroy(admin_session, inst, engine)
    admin_session.flush()
    assert out.status == "reaped"
    assert stopped == [inst.id]
    engine.destroy.assert_called_once_with("dal-stop")
    admin_session.rollback()


def test_provision_records_error_when_failure_occurs_before_deploy_is_invoked(
    admin_session, tenant_a, monkeypatch
):
    """A failure before ``engine.deploy()`` is ever called (e.g. topology
    interpolation) proves no runtime was created — nothing to conservatively
    protect, so the instance is recorded ``error`` as before."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-err", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()

    def _boom(text, seed):
        raise ValueError("bad topology template")

    monkeypatch.setattr(lab_lifecycle, "interpolate", _boom)
    engine = MagicMock()
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "error"
    assert "bad topology template" in out.error
    engine.deploy.assert_not_called()
    admin_session.rollback()


def test_provision_deploy_failure_leaves_instance_active_with_error_recorded(
    admin_session, tenant_a
):
    """A failure FROM/AFTER ``engine.deploy()`` does not prove the runtime is
    absent (the containerlab process may still be running), so — mirroring
    ``_run_deploy``'s destroy-failure handling — the instance conservatively
    stays ``active`` rather than ``error``, with the failure text still
    recorded on ``instance.error`` for callers that key off it."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-err", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy.side_effect = RuntimeError("boom")
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"
    assert "boom" in out.error
    admin_session.rollback()


def test_provision_deploy_failure_still_counts_against_capacity(
    admin_session, tenant_a, monkeypatch
):
    """The phantom-but-conservative ``active`` instance from a failed deploy
    must still occupy a capacity slot — otherwise a second admission could
    exceed the real limit while the (possibly still-running) old lab lingers
    until the next ``reconcile_runtime`` pass."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-err-cap", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy.side_effect = RuntimeError("boom")
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"

    monkeypatch.setattr(settings, "max_concurrent_labs", 1)
    candidate = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                            instance_name="dal-second", seed={"o": 6},
                            status="queued", consoles={})
    admin_session.add(candidate)
    admin_session.flush()
    assert lab_operations._capacity_available(admin_session, candidate) is False
    admin_session.rollback()


def test_provision_host_lock_unavailable_passes_through_unchanged(admin_session, tenant_a):
    """Host-lock contention is transient contention handled by a different
    layer (``run_claimed``), not a deployment failure — it must propagate
    unchanged, without provision() converting it into an error/active status
    change."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-lock", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy.side_effect = HostLockUnavailable("host lock held")

    with pytest.raises(HostLockUnavailable):
        lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert inst.status == "provisioning"
    assert inst.error is None
    admin_session.rollback()


def test_reset_success_sets_active_clears_error_and_updates_last_active(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reset-ok", seed={"o": 5}, status="error",
                       error="stale failure from a prior reset",
                       consoles={"client": {"kind": "linux", "mgmt": "172.20.20.9"}})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.reset.return_value = LabHandle(
        instance_name="dal-reset-ok", nodes={"client": "clab-dal-reset-ok-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"
    assert out.error is None
    assert out.last_active_at is not None
    engine.reset.assert_called_once()
    admin_session.rollback()


def test_reset_applies_topology_name_before_calling_engine(admin_session, tenant_a):
    """reset() must apply _set_topology_name() the same way provision() does,
    so the redeployed containers still follow the clab-<instance>-<node>
    convention handle_for expects — a raw interpolate() with no name override
    would leave the topology's original `name:` (or none) in place."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reset-name", seed={"o": 5}, status="active",
                       consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.reset.return_value = LabHandle(
        instance_name="dal-reset-name", nodes={"client": "clab-dal-reset-name-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    topology_text_used = engine.reset.call_args[0][0]
    assert "name: dal-reset-name" in topology_text_used
    admin_session.rollback()


def test_reset_success_rebuilds_consoles_from_fresh_handle(admin_session, tenant_a):
    """A successful reset must not leave stale mgmt/console data on the row —
    engine.reset() can return different mgmt IPs/ports on redeploy."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reset-consoles", seed={"o": 5}, status="active",
                       consoles={"client": {"kind": "linux", "mgmt": "172.20.20.9", "port": 1111}})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.reset.return_value = LabHandle(
        instance_name="dal-reset-consoles",
        nodes={"client": "clab-dal-reset-consoles-client", "r1": "clab-dal-reset-consoles-r1"},
        mgmt={"client": "172.20.20.55", "r1": "172.20.20.2"},
        kinds={"client": "linux", "r1": "vr-ros"})
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    # Fresh mgmt IP replaces the stale one, and a node that didn't exist
    # before the reset is now present.
    assert out.consoles["client"]["mgmt"] == "172.20.20.55"
    assert "r1" in out.consoles
    assert "port" not in out.consoles["r1"]  # RouterOS gets webfig, not ttyd
    admin_session.rollback()


def test_reset_stops_old_consoles_before_starting_fresh_ones(admin_session, tenant_a, monkeypatch):
    """stop_consoles() matches running ttyd processes by instance.id alone (not
    by port), so it MUST run before the fresh start_console() calls — calling
    it after would kill the just-started consoles for the same instance."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reset-order", seed={"o": 5}, status="active",
                       consoles={"client": {"kind": "linux", "mgmt": "172.20.20.9", "port": 1111}})
    admin_session.add(inst)
    admin_session.flush()

    calls: list[str] = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: calls.append("stop") or 1)

    def _fake_start_console(cname, base_path):
        calls.append("start")
        return 9999

    monkeypatch.setattr(lab_lifecycle, "start_console", _fake_start_console)
    engine = MagicMock()
    engine.reset.return_value = LabHandle(
        instance_name="dal-reset-order", nodes={"client": "clab-dal-reset-order-client"},
        mgmt={"client": "172.20.20.55"}, kinds={"client": "linux"})
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()

    assert calls == ["stop", "start"]
    assert out.consoles["client"]["port"] == 9999
    admin_session.rollback()


def test_reset_refuses_a_reaped_instance_without_touching_the_engine(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reaped", seed={"o": 5}, status="reaped",
                       consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()

    with pytest.raises(ConflictError):
        lab_lifecycle.reset(admin_session, inst, engine, lt)
    engine.reset.assert_not_called()
    admin_session.rollback()


def test_reset_refuses_a_queued_instance_without_touching_the_engine(admin_session, tenant_a):
    """queued is lab_operations.run_claimed()'s capacity-controlled path —
    resetting a queued instance directly would deploy it immediately and
    bypass MAX_CONCURRENT_LABS entirely."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-queued", seed={"o": 5}, status="queued",
                       consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()

    with pytest.raises(ConflictError):
        lab_lifecycle.reset(admin_session, inst, engine, lt)
    engine.reset.assert_not_called()
    admin_session.rollback()


def test_reset_refuses_a_provisioning_instance_without_touching_the_engine(admin_session, tenant_a):
    """provisioning means the worker's own provision() may be running against
    this exact row/work directory right now — resetting it too would race
    that in-flight deploy."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-provisioning", seed={"o": 5}, status="provisioning",
                       consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()

    with pytest.raises(ConflictError):
        lab_lifecycle.reset(admin_session, inst, engine, lt)
    engine.reset.assert_not_called()
    admin_session.rollback()


def test_reset_failure_records_error_and_does_not_raise(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reset-err", seed={"o": 5}, status="active",
                       consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.reset.side_effect = RuntimeError("engine boom")
    # Must not raise out of the service function.
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "error"
    assert "engine boom" in out.error
    admin_session.rollback()


def test_grade_writes_score_and_submission(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-test", seed={"o": 5}, status="active", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.exec.return_value = ExecResult(
        stdout="1 packets transmitted, 1 received", stderr="", exit_code=0)
    handle = LabHandle(instance_name="dal-test", nodes={"client": "clab-x-client"},
                       mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    score = lab_lifecycle.grade(admin_session, inst, engine, lt, handle)
    admin_session.flush()
    assert score.max_score > 0
    assert score.passed is True
    assert score.per_item  # non-empty
    assert score.source == "auto"
    sub = admin_session.scalars(
        select(Submission).where(Submission.id == score.submission_id)).first()
    assert sub is not None
    assert sub.answers["seed"] == {"o": 5}
    assert sub.answers["instance"] == str(inst.id)
    admin_session.rollback()


@pytest.mark.parametrize("status", ["queued", "provisioning", "resetting", "error", "reaped"])
def test_grade_refuses_non_active_without_writing_submission(
    admin_session, tenant_a, status
):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=p.id,
        instance_name=f"dal-grade-{status}",
        seed={"o": 5},
        status=status,
        consoles={},
    )
    admin_session.add(inst)
    admin_session.flush()
    before = admin_session.query(Submission).count()
    engine = MagicMock()

    with pytest.raises(ConflictError):
        lab_lifecycle.grade(
            admin_session,
            inst,
            engine,
            lt,
            LabHandle(instance_name=inst.instance_name, nodes={}, mgmt={}, kinds={}),
        )

    assert admin_session.query(Submission).count() == before
    engine.exec.assert_not_called()
    engine.ssh_exec.assert_not_called()
    admin_session.rollback()


def test_grade_refuses_degraded_active_without_writing_submission(
    admin_session, tenant_a
):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=p.id,
        instance_name="dal-grade-degraded",
        seed={"o": 5},
        status="active",
        error="destroy failed; external resources may still exist",
        consoles={},
    )
    admin_session.add(inst)
    admin_session.flush()
    before = admin_session.query(Submission).count()
    engine = MagicMock()

    with pytest.raises(ConflictError):
        lab_lifecycle.grade(
            admin_session,
            inst,
            engine,
            lt,
            LabHandle(instance_name=inst.instance_name, nodes={}, mgmt={}, kinds={}),
        )

    assert admin_session.query(Submission).count() == before
    engine.exec.assert_not_called()
    engine.ssh_exec.assert_not_called()
    admin_session.rollback()


def test_destroy_marks_reaped(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-destroy", seed={"o": 5}, status="active", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    out = lab_lifecycle.destroy(admin_session, inst, engine)
    admin_session.flush()
    assert out.status == "reaped"
    engine.destroy.assert_called_once_with("dal-destroy")
    admin_session.rollback()


# --- console bind guard + orphan bookkeeping -------------------------------
# Regression cover for the leak found on the academy host 2026-08-14: 14 ttyd
# processes spinning at ~99% CPU each for up to 15 days, spawned with an ``-i``
# address the host did not own. ttyd never exits in that case — it retries the
# bind forever — so the guard has to refuse BEFORE spawning.


def test_console_bind_host_defaults_to_the_dial_host(monkeypatch):
    monkeypatch.setattr(settings, "lab_console_host", "10.99.0.2")
    monkeypatch.setattr(settings, "lab_console_bind_host", "")
    assert lab_lifecycle.console_bind_host() == "10.99.0.2"


def test_console_bind_host_is_independent_of_the_dial_host(monkeypatch):
    monkeypatch.setattr(settings, "lab_console_host", "10.99.0.2")
    monkeypatch.setattr(settings, "lab_console_bind_host", "127.0.0.1")
    assert lab_lifecycle.console_bind_host() == "127.0.0.1"


def test_start_console_refuses_a_non_local_bind_address(monkeypatch):
    """The whole bug in one test: a remote bind address must not spawn ttyd."""
    monkeypatch.setattr(lab_lifecycle.shutil, "which", lambda _: "/usr/bin/ttyd")
    monkeypatch.setattr(settings, "lab_console_bind_host", "10.99.0.2")

    spawned = []
    monkeypatch.setattr(lab_lifecycle, "_is_local_address", lambda host: False)
    monkeypatch.setattr(lab_lifecycle.subprocess, "Popen",
                        lambda *a, **k: spawned.append(a))

    assert _REAL_START_CONSOLE("clab-x-client", "/labs/instances/abc/console/client") is None
    assert spawned == []


def test_start_console_spawns_when_the_bind_address_is_local(monkeypatch):
    monkeypatch.setattr(lab_lifecycle.shutil, "which", lambda _: "/usr/bin/ttyd")
    monkeypatch.setattr(settings, "lab_console_bind_host", "127.0.0.1")

    spawned = []
    monkeypatch.setattr(lab_lifecycle.subprocess, "Popen",
                        lambda argv, **k: spawned.append(argv))

    port = _REAL_START_CONSOLE("clab-x-client", "/labs/instances/abc/console/client")
    assert port is not None
    assert spawned and spawned[0][:5] == ["ttyd", "-p", str(port), "-i", "127.0.0.1"]


def test_is_local_address_accepts_loopback_and_rejects_a_foreign_address():
    assert lab_lifecycle._is_local_address("127.0.0.1") is True
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — never assigned to a real interface.
    assert lab_lifecycle._is_local_address("192.0.2.1") is False


def test_console_pids_parses_the_instance_id_out_of_the_base_path(monkeypatch):
    out = (
        "111 ttyd -p 40000 -i 127.0.0.1 -b /labs/instances/aaaa-1/console/client -W docker exec -it c sh\n"
        "222 ttyd -p 40001 -i 127.0.0.1 -b /labs/instances/aaaa-1/console/r1 -W docker exec -it c sh\n"
        "333 ttyd -p 40002 -i 127.0.0.1 -b /labs/instances/bbbb-2/console/client -W docker exec -it c sh\n"
    )
    monkeypatch.setattr(lab_lifecycle.subprocess, "run",
                        lambda *a, **k: MagicMock(stdout=out))
    assert lab_lifecycle.console_pids() == {"aaaa-1": [111, 222], "bbbb-2": [333]}


def test_kill_consoles_counts_only_what_it_signalled(monkeypatch):
    signalled = []

    def _kill(pid, sig):
        if pid == 999:
            raise ProcessLookupError  # already exited between scan and kill
        signalled.append(pid)

    monkeypatch.setattr(lab_lifecycle.os, "kill", _kill)
    assert lab_lifecycle.kill_consoles([111, 999, 222]) == 2
    assert signalled == [111, 222]


# --- runtime_presence transitions ------------------------------------------


def test_request_lab_is_absent_after_flush(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                     person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    assert inst.runtime_presence == "absent"
    admin_session.rollback()


def test_provision_pre_deploy_failure_sets_absent(admin_session, tenant_a, monkeypatch):
    """Nothing was ever attempted, so presence is "absent", not just status."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-preflight", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()

    def _boom(text, seed):
        raise ValueError("bad topology template")

    monkeypatch.setattr(lab_lifecycle, "interpolate", _boom)
    engine = MagicMock()
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "error"
    assert out.runtime_presence == "absent"
    engine.deploy.assert_not_called()
    admin_session.rollback()


def test_provision_deploy_failure_sets_unknown(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-invoke-fail", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy.side_effect = RuntimeError("boom")
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"
    assert out.runtime_presence == "unknown"
    admin_session.rollback()


def test_provision_success_sets_present(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-success", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name="dal-presence-success", nodes={"client": "clab-x-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    out = lab_lifecycle.provision(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"
    assert out.runtime_presence == "present"
    admin_session.rollback()


def test_reset_pre_call_failure_preserves_prior_presence(admin_session, tenant_a, monkeypatch):
    """A failure before engine.reset() is ever invoked (topology
    interpolation) must leave the PRIOR presence value untouched."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-reset-preflight", seed={"o": 5},
                       status="active", consoles={})
    inst.runtime_presence = "present"
    admin_session.add(inst)
    admin_session.flush()

    def _boom(text, seed):
        raise ValueError("bad topology template")

    monkeypatch.setattr(lab_lifecycle, "interpolate", _boom)
    engine = MagicMock()
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "error"
    assert out.runtime_presence == "present"  # unchanged — reset() was never invoked
    engine.reset.assert_not_called()
    admin_session.rollback()


def test_reset_invocation_failure_sets_unknown(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-reset-fail", seed={"o": 5},
                       status="active", consoles={})
    inst.runtime_presence = "present"
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.reset.side_effect = RuntimeError("engine boom")
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "error"
    assert out.runtime_presence == "unknown"
    admin_session.rollback()


def test_reset_success_sets_present(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-reset-ok", seed={"o": 5}, status="error",
                       consoles={})
    inst.runtime_presence = "unknown"
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.reset.return_value = LabHandle(
        instance_name="dal-presence-reset-ok", nodes={"client": "clab-x-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    out = lab_lifecycle.reset(admin_session, inst, engine, lt)
    admin_session.flush()
    assert out.status == "active"
    assert out.runtime_presence == "present"
    admin_session.rollback()


def test_destroy_success_sets_absent(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-presence-destroy", seed={"o": 5}, status="active",
                       consoles={})
    inst.runtime_presence = "present"
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    out = lab_lifecycle.destroy(admin_session, inst, engine)
    admin_session.flush()
    assert out.status == "reaped"
    assert out.runtime_presence == "absent"
    admin_session.rollback()


def test_provision_if_absent_deploys_when_precondition_holds(admin_session, tenant_a):
    """Precondition (absent) confirmed by ``deploy_if_absent`` returning a
    real handle: proceeds exactly like an ordinary successful deploy."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-cond-deploy-ok", seed={"o": 5},
                       status="provisioning", consoles={})
    inst.runtime_presence = "unknown"
    admin_session.add(inst)
    admin_session.flush()
    engine = MagicMock()
    engine.deploy_if_absent.return_value = LabHandle(
        instance_name="dal-cond-deploy-ok", nodes={"client": "clab-x-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})
    out = lab_lifecycle.provision_if_absent(
        admin_session, inst, engine, lt,
        preserved_status="active", preserved_error=None,
    )
    admin_session.flush()
    assert out.status == "active"
    assert out.runtime_presence == "present"
    assert out.consoles["client"]["mgmt"] == "172.20.20.3"
    assert out.started_at is not None
    engine.deploy_if_absent.assert_called_once()
    admin_session.rollback()


def test_provision_if_absent_settles_noop_without_any_mutation_when_precondition_mismatched(
    admin_session, tenant_a, monkeypatch
):
    """``deploy_if_absent`` returning ``None`` means the runtime was found
    genuinely present — this is the no-op path. Nothing may be mutated:
    status/error are restored to their pre-admission values, consoles stay
    untouched, and only runtime_presence is refreshed."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-cond-deploy-noop", seed={"o": 5},
                       status="provisioning", consoles={"stale": {"kind": "linux"}})
    inst.runtime_presence = "unknown"
    inst.error = "stale error text"
    admin_session.add(inst)
    admin_session.flush()

    stopped = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: stopped.append(i.id))
    started = []
    monkeypatch.setattr(lab_lifecycle, "start_console", lambda c, b: started.append(c) or 1)

    engine = MagicMock()
    engine.deploy_if_absent.return_value = None  # precondition mismatch: genuinely present

    out = lab_lifecycle.provision_if_absent(
        admin_session, inst, engine, lt,
        preserved_status="active", preserved_error="stale error text",
    )
    admin_session.flush()
    assert out.status == "active"  # restored to preserved_status, not "provisioning"
    assert out.error == "stale error text"  # restored to preserved_error
    assert out.consoles == {"stale": {"kind": "linux"}}  # completely untouched
    assert out.runtime_presence == "present"  # refreshed from the fresh observation
    assert stopped == []  # no console teardown on the no-op path
    assert started == []  # no console recreation on the no-op path
    engine.deploy.assert_not_called()
    admin_session.rollback()


def test_destroy_if_present_destroys_and_stops_consoles_only_after_real_destroy(
    admin_session, tenant_a, monkeypatch
):
    _c, act, _lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-cond-destroy-ok", seed={"o": 5}, status="active",
                       consoles={"client": {"kind": "linux"}})
    inst.runtime_presence = "present"
    admin_session.add(inst)
    admin_session.flush()
    order = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: order.append("stop_consoles"))
    engine = MagicMock()
    engine.destroy_if_present.side_effect = lambda name: order.append("destroy_if_present") or True

    out = lab_lifecycle.destroy_if_present(admin_session, inst, engine)
    admin_session.flush()
    assert out.status == "reaped"
    assert out.runtime_presence == "absent"
    assert order == ["destroy_if_present", "stop_consoles"]  # destroy before teardown
    admin_session.rollback()


def test_destroy_if_present_settles_noop_without_any_mutation_when_precondition_mismatched(
    admin_session, tenant_a, monkeypatch
):
    """``destroy_if_present`` returning ``False`` means the runtime was
    already absent — this is the no-op path. status/error/consoles stay
    exactly as they were; only runtime_presence is refreshed to "absent"."""
    _c, act, _lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-cond-destroy-noop", seed={"o": 5}, status="reaped",
                       consoles={"client": {"kind": "linux"}})
    inst.error = "pre-existing error"
    inst.runtime_presence = "unknown"
    admin_session.add(inst)
    admin_session.flush()
    stopped = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: stopped.append(i.id))
    engine = MagicMock()
    engine.destroy_if_present.return_value = False

    out = lab_lifecycle.destroy_if_present(admin_session, inst, engine)
    admin_session.flush()
    assert out.status == "reaped"  # untouched
    assert out.error == "pre-existing error"  # untouched
    assert out.consoles == {"client": {"kind": "linux"}}  # untouched
    assert out.runtime_presence == "absent"  # refreshed from the fresh observation
    assert stopped == []  # no console teardown on the no-op path
    admin_session.rollback()


def test_the_no_real_spawn_guard_still_bites():
    """The guard is about the NEXT forgotten patch, not the last one.

    ``test_provision_sets_consoles_and_active`` calls provision WITHOUT patching
    start_console, and used to spawn a real ttyd on any host with the binary
    installed. If the autouse fixture ever stops applying, this fails loudly
    instead of quietly leaking daemons again.
    """
    assert lab_lifecycle.start_console is not _REAL_START_CONSOLE
    assert lab_lifecycle.start_console("clab-x-client", "/labs/instances/x/console/client") is None
