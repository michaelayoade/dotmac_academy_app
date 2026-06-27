"""TDD tests for the lab lifecycle service (Task 6): quota + grade-to-ledger."""

from unittest.mock import MagicMock

from sqlalchemy import select

from app.config import settings
from app.models.assessment import Activity, Submission
from app.models.course import Course
from app.models.lab import LabInstance, LabTemplate
from app.models.person import Person
from app.services import lab_lifecycle
from app.services.labengine.interface import ExecResult, LabHandle


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
    from uuid import uuid4
    pid, aid = uuid4(), uuid4()
    name = lab_lifecycle.instance_name(tenant_a.id, pid, aid, 1)
    assert name == f"dal-{str(tenant_a.id)[:8]}-{str(pid)[:8]}-{str(aid)[:8]}-1"


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


def test_request_lab_provisions_with_capacity(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    monkeypatch.setattr(settings, "max_concurrent_labs", 20)
    inst = lab_lifecycle.request_lab(admin_session, tenant_id=tenant_a.id,
                                     person_id=p.id, activity=act, template=lt)
    admin_session.flush()
    assert inst.status == "provisioning"
    assert lab_lifecycle.active_count(admin_session, tenant_a.id) == 1
    admin_session.rollback()


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


def test_provision_records_error_on_failure(admin_session, tenant_a):
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
    assert out.status == "error"
    assert "boom" in out.error
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
