"""TDD tests for the cross-tenant lab worker/reaper jobs (Task 7).

These jobs OWN their transaction (they ``commit``). The tests pass the conftest
``admin_session`` (a BYPASSRLS Session) directly into the functions rather than
opening a new admin connection, and clean up by letting ``tenant_a`` CASCADE.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.config import settings
from app.models.assessment import Activity
from app.models.course import Course
from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.models.person import Person
from app.services import lab_jobs, lab_operations
from app.services.labengine.interface import LabHandle


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
        checks=[{"id": "c1", "type": "probe"}],
        seed_spec={"o": {"type": "int", "min": 2, "max": 9}},
        limits={"time_minutes": 45},
    )
    db.add(lt)
    db.flush()
    p = Person(tenant_id=tid, email="trainee@example.com", first_name="T", last_name="U")
    db.add(p)
    db.flush()
    return c, act, lt, p


def test_worker_session_refuses_a_non_worker_dsn(monkeypatch):
    monkeypatch.setattr(
        settings,
        "lab_worker_database_url",
        "postgresql+psycopg://postgres@db/academy",
    )
    with pytest.raises(RuntimeError, match="must authenticate as academy_lab_worker"):
        with lab_jobs.lab_worker_session():
            pytest.fail("must refuse before opening a session")


def test_worker_session_refuses_worker_without_bypassrls(monkeypatch):
    """A live worker role that has lost BYPASSRLS must fail loudly, not go quiet.

    Regression coverage for the guard added alongside the ``current_user``
    check: ``lab_operations`` has FORCE ROW LEVEL SECURITY, so a worker
    connection without BYPASSRLS would otherwise silently see an empty queue
    instead of raising. This mocks the DB round-trips so it never needs a live
    Postgres connection — only the URL-username prefilter is real.
    """
    monkeypatch.setattr(
        settings,
        "lab_worker_database_url",
        "postgresql+psycopg://academy_lab_worker@db/academy",
    )
    fake_session = MagicMock()
    fake_session.scalar.side_effect = ["academy_lab_worker", False]
    monkeypatch.setattr(lab_jobs, "create_engine", lambda *a, **k: MagicMock())
    monkeypatch.setattr(lab_jobs, "sessionmaker", lambda *a, **k: (lambda: fake_session))

    with pytest.raises(RuntimeError, match="does not have BYPASSRLS"):
        with lab_jobs.lab_worker_session():
            pytest.fail("must refuse before yielding a session")
    assert fake_session.scalar.call_count == 2
    fake_session.close.assert_called_once()


def test_worker_session_refuses_worker_that_owns_application_objects(monkeypatch):
    monkeypatch.setattr(
        settings,
        "lab_worker_database_url",
        "postgresql+psycopg://academy_lab_worker@db/academy",
    )
    fake_session = MagicMock()
    fake_session.scalar.side_effect = ["academy_lab_worker", True, True, True]
    monkeypatch.setattr(lab_jobs, "create_engine", lambda *a, **k: MagicMock())
    monkeypatch.setattr(lab_jobs, "sessionmaker", lambda *a, **k: (lambda: fake_session))

    with pytest.raises(RuntimeError, match="must not own"):
        with lab_jobs.lab_worker_session():
            pytest.fail("must refuse an owning worker role")
    fake_session.close.assert_called_once()


def test_worker_session_refuses_unsafe_role_attributes(monkeypatch):
    monkeypatch.setattr(
        settings,
        "lab_worker_database_url",
        "postgresql+psycopg://academy_lab_worker@db/academy",
    )
    fake_session = MagicMock()
    fake_session.scalar.side_effect = ["academy_lab_worker", True, False]
    monkeypatch.setattr(lab_jobs, "create_engine", lambda *a, **k: MagicMock())
    monkeypatch.setattr(lab_jobs, "sessionmaker", lambda *a, **k: (lambda: fake_session))

    with pytest.raises(RuntimeError, match="unsafe attributes or role memberships"):
        with lab_jobs.lab_worker_session():
            pytest.fail("must refuse unsafe role posture")
    fake_session.close.assert_called_once()


def test_drain_once_provisions_pending(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    monkeypatch.setattr(settings, "max_concurrent_labs", 20)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-drain", seed={"o": 5},
                       status="queued", consoles={})
    admin_session.add(inst)
    admin_session.flush()
    lab_operations.enqueue(admin_session, instance=inst, kind="deploy", requested_by=p.id)
    admin_session.commit()

    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name="dal-drain", nodes={"client": "clab-x-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})

    n = lab_jobs.drain_once(admin_session, engine)

    assert n == 1
    admin_session.refresh(inst)
    assert inst.status == "active"
    engine.deploy.assert_called_once()


def test_reap_idle_enqueues_destroy_without_touching_engine(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reap", seed={"o": 5},
                       status="active", consoles={},
                       last_active_at=datetime.now(UTC) - timedelta(minutes=999))
    admin_session.add(inst)
    admin_session.commit()

    n = lab_jobs.request_idle_reaps(admin_session)

    assert n == 1
    admin_session.refresh(inst)
    assert inst.status == "active"
    operation = admin_session.query(LabOperation).filter_by(instance_id=inst.id).one()
    assert operation.kind == "destroy"
    assert operation.state == "queued"


def test_sweep_kills_consoles_whose_instance_is_not_live(admin_session, tenant_a, monkeypatch):
    """The backstop: a console outliving its instance gets reaped on the timer."""
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    live = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-live", seed={"o": 5}, status="active", consoles={})
    dead = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-dead", seed={"o": 5}, status="reaped", consoles={})
    admin_session.add_all([live, dead])
    admin_session.flush()

    monkeypatch.setattr(lab_jobs, "console_pids", lambda: {
        str(live.id): [111],
        str(dead.id): [222, 333],
        "11111111-2222-3333-4444-555555555555": [444],  # no row at all
    })
    killed = []
    monkeypatch.setattr(lab_jobs, "kill_consoles",
                        lambda pids: killed.extend(pids) or len(killed))

    assert lab_jobs.sweep_orphan_consoles(admin_session) == 3
    assert sorted(killed) == [222, 333, 444]  # the live instance's console survives
    admin_session.rollback()


def test_sweep_is_a_no_op_when_no_consoles_are_running(admin_session, monkeypatch):
    monkeypatch.setattr(lab_jobs, "console_pids", lambda: {})
    monkeypatch.setattr(lab_jobs, "kill_consoles",
                        lambda pids: pytest.fail("must not kill anything"))
    assert lab_jobs.sweep_orphan_consoles(admin_session) == 0


def test_runtime_reconcile_queues_destroy_for_reaped_row_with_live_runtime(
    admin_session, tenant_a
):
    _c, act, _lt, p = _seed(admin_session, tenant_a.id)
    instance = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=p.id,
        instance_name="dal-runtime-leak",
        seed={},
        status="reaped",
        consoles={},
    )
    admin_session.add(instance)
    admin_session.flush()
    engine = MagicMock()
    engine.inventory.return_value = {instance.instance_name: "/labs/leak.clab.yml"}

    assert lab_jobs.reconcile_runtime(admin_session, engine) == (1, 0)
    assert instance.status == "active"
    operation = admin_session.query(LabOperation).filter_by(instance_id=instance.id).one()
    assert operation.kind == "destroy"
    engine.destroy.assert_not_called()
    admin_session.rollback()


def test_runtime_reconcile_destroys_only_rowless_academy_labs(
    admin_session, tenant_a
):
    engine = MagicMock()
    engine.inventory.return_value = {
        "dal-rowless": "/labs/rowless.clab.yml",
        "shared-infrastructure": "/labs/shared.clab.yml",
    }

    assert lab_jobs.reconcile_runtime(admin_session, engine) == (0, 1)
    engine.destroy.assert_called_once_with("dal-rowless")
    admin_session.rollback()


def test_runtime_reconcile_queues_replay_for_live_row_without_runtime(
    admin_session, tenant_a
):
    _c, act, _lt, p = _seed(admin_session, tenant_a.id)
    instance = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=p.id,
        instance_name="dal-runtime-missing",
        seed={},
        status="active",
        consoles={},
    )
    admin_session.add(instance)
    admin_session.flush()
    engine = MagicMock()
    engine.inventory.return_value = {}

    assert lab_jobs.reconcile_runtime(admin_session, engine) == (1, 0)
    operation = admin_session.query(LabOperation).filter_by(instance_id=instance.id).one()
    assert operation.kind == "deploy"
    assert "no containerlab runtime" in instance.error
    admin_session.rollback()


def test_runtime_reconcile_releases_confirmed_absent_degraded_capacity(
    admin_session, tenant_a
):
    _c, act, _lt, p = _seed(admin_session, tenant_a.id)
    instance = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=p.id,
        instance_name="dal-runtime-confirmed-absent",
        seed={},
        status="active",
        error="worker lease expired after 3 attempts",
        consoles={},
    )
    admin_session.add(instance)
    admin_session.flush()
    engine = MagicMock()
    engine.inventory.return_value = {}

    assert lab_jobs.reconcile_runtime(admin_session, engine) == (0, 0)
    assert instance.status == "error"
    assert "runtime is absent" in instance.error
    assert (
        admin_session.query(LabOperation)
        .filter_by(instance_id=instance.id)
        .count()
        == 0
    )
    admin_session.rollback()


def test_runtime_reconcile_does_not_act_on_a_snapshot_made_stale_by_a_concurrent_reset(
    admin_session, tenant_a
):
    """Phase 4 must re-validate, not trust, Phase 2's snapshot.

    ``missing_runtime`` is computed once, in Phase 2, before Phase 3's
    (potentially multi-minute, per orphan) destroy loop runs. If a real,
    concurrent, user-initiated reset completes for one of those instances
    while Phase 3 is still running, Phase 4 must not enqueue a destroy
    against it using the now-stale Phase 2 snapshot — that would tear down a
    lab that just came back up.

    The concurrent mutation is injected via ``engine.destroy``'s side effect
    for the one rowless orphan this test also seeds — ``engine.destroy`` is
    the last thing Phase 3 does before Phase 4 runs, so performing the
    "concurrent" enqueue from inside it deterministically reproduces "some
    real time and a real database write happened between Phase 2 and Phase
    4" without needing an actual second thread or process.
    """
    _c, act, _lt, p = _seed(admin_session, tenant_a.id)
    instance = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=p.id,
        instance_name="dal-race-missing-runtime",
        seed={},
        status="active",
        consoles={},
    )
    admin_session.add(instance)
    admin_session.flush()

    def _concurrent_reset_during_phase_3(name: str) -> None:
        assert name == "dal-rowless-race-trigger"
        # Simulate a real worker completing an unrelated, concurrent
        # user-initiated redeploy for `instance` while this destroy is
        # "in flight" — it now has a genuinely open operation.
        lab_operations.enqueue(admin_session, instance=instance, kind="deploy", requested_by=p.id)
        admin_session.flush()

    engine = MagicMock()
    engine.inventory.return_value = {
        "dal-rowless-race-trigger": "/labs/rowless-race-trigger.clab.yml",
    }
    engine.destroy.side_effect = _concurrent_reset_during_phase_3

    queued, destroyed = lab_jobs.reconcile_runtime(admin_session, engine)

    assert destroyed == 1
    engine.destroy.assert_called_once_with("dal-rowless-race-trigger")
    # The concurrent deploy is the only operation queued for `instance` — no
    # destroy/deploy was ALSO enqueued against the stale Phase 2 snapshot.
    ops = (
        admin_session.query(LabOperation)
        .filter_by(instance_id=instance.id)
        .all()
    )
    assert [op.kind for op in ops] == ["deploy"]
    assert queued == 0
    # Untouched by Phase 4 — it was skipped, not mutated.
    assert instance.status == "active"
    assert instance.error is None
    admin_session.rollback()
