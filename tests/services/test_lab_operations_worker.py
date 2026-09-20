"""Worker ownership, fencing, recovery, and admission tests."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.assessment import Activity, Submission
from app.models.course import Course
from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.models.person import Person
from app.services import host_lock, lab_jobs, lab_lifecycle, lab_operations
from app.services.exceptions import ConflictError
from app.services.labengine.containerlab import ContainerlabEngine
from app.services.labengine.interface import LabHandle


def _seed(db, tenant_id, *, name: str = "one", status: str = "queued", presence: str | None = None):
    course = Course(
        tenant_id=tenant_id,
        slug=f"worker-{name}",
        title="Worker",
        discipline="networking",
        source_ref="test",
        version=1,
    )
    db.add(course)
    db.flush()
    activity = Activity(
        tenant_id=tenant_id,
        course_id=course.id,
        chapter_number=1,
        type="lab",
        title="Worker lab",
        pass_threshold=0.5,
    )
    db.add(activity)
    db.flush()
    template = LabTemplate(
        tenant_id=tenant_id,
        course_id=course.id,
        chapter_number=1,
        activity_id=activity.id,
        slug=f"worker-{name}",
        title="Worker lab",
        topology="name: placeholder",
        instructions_html="<p>test</p>",
        checks=[],
        seed_spec={},
        limits={},
        source_hash="test",
        version=1,
    )
    person = Person(
        tenant_id=tenant_id,
        email=f"worker-{name}@example.test",
        first_name="Lab",
        last_name="Worker",
    )
    db.add_all([template, person])
    db.flush()
    instance = LabInstance(
        tenant_id=tenant_id,
        activity_id=activity.id,
        person_id=person.id,
        instance_name=f"dal-worker-{name}",
        seed={},
        status=status,
        consoles={},
    )
    if presence is None:
        # Preserve prior (status-derived) capacity semantics for every
        # existing caller that doesn't care about presence directly: a
        # "provisioning"/"active"/"resetting" seed is a stand-in for a
        # successfully-running lab ("present"); anything else defaults to
        # "absent". Callers exercising presence/status divergence directly
        # pass an explicit `presence=`.
        presence = "present" if status in ("provisioning", "active", "resetting") else "absent"
    instance.runtime_presence = presence
    db.add(instance)
    db.flush()
    return instance, person


def _engine(instance_name: str):
    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name=instance_name,
        nodes={},
        mgmt={},
        kinds={},
    )
    return engine


def test_duplicate_requests_collapse_to_one_open_operation(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id)
    first = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    second = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    assert first.id == second.id
    assert admin_session.query(LabOperation).filter_by(instance_id=instance.id).count() == 1
    admin_session.rollback()


def test_competing_claims_claim_an_operation_once(admin_engine, admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id)
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation_id = operation.id
    admin_session.commit()

    factory = sessionmaker(bind=admin_engine, autoflush=False)
    first = factory()
    second = factory()
    try:
        claimed = lab_operations.claim_next(first, claimed_by="worker-one")
        assert claimed is not None and claimed.id == operation_id
        # The first transaction still holds the row lock. SKIP LOCKED means the
        # competing poller observes no claimable row instead of waiting.
        assert lab_operations.claim_next(second, claimed_by="worker-two") is None
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()


def test_competing_pollers_claim_each_operation_exactly_once(
    admin_engine, admin_session, tenant_a
):
    operation_ids = []
    for index in range(10):
        instance, person = _seed(
            admin_session, tenant_a.id, name=f"claim-{index}"
        )
        operation_ids.append(
            lab_operations.enqueue(
                admin_session,
                instance=instance,
                kind="deploy",
                requested_by=person.id,
            ).id
        )
    admin_session.commit()
    factory = sessionmaker(bind=admin_engine, autoflush=False)
    start = Barrier(2)

    def _poller(number: int):
        db = factory()
        claimed_ids = []
        try:
            start.wait(timeout=5)
            while True:
                operation = lab_operations.claim_next(
                    db, claimed_by=f"claim-worker-{number}"
                )
                if operation is None:
                    db.rollback()
                    return claimed_ids
                claimed_ids.append(operation.id)
                db.commit()
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = list(pool.map(_poller, (1, 2)))

    flattened = [operation_id for worker_ids in claimed for operation_id in worker_ids]
    assert len(flattened) == 10
    assert set(flattened) == set(operation_ids)


def test_destroy_has_priority_over_older_deploy(admin_session, tenant_a):
    deploy_instance, person = _seed(admin_session, tenant_a.id, name="deploy")
    destroy_instance, _ = _seed(admin_session, tenant_a.id, name="destroy", status="active")
    lab_operations.enqueue(
        admin_session, instance=deploy_instance, kind="deploy", requested_by=person.id
    )
    destroy = lab_operations.enqueue(
        admin_session, instance=destroy_instance, kind="destroy", requested_by=None
    )
    admin_session.flush()

    claimed = lab_operations.claim_next(admin_session, claimed_by="worker")
    assert claimed is not None
    assert claimed.id == destroy.id
    admin_session.rollback()


def test_check_has_priority_over_older_deploy(admin_session, tenant_a):
    deploy_instance, person = _seed(admin_session, tenant_a.id, name="deploy-priority")
    check_instance, _ = _seed(
        admin_session, tenant_a.id, name="check-priority", status="active"
    )
    lab_operations.enqueue(
        admin_session, instance=deploy_instance, kind="deploy", requested_by=person.id
    )
    check = lab_operations.enqueue(
        admin_session, instance=check_instance, kind="check", requested_by=person.id
    )
    admin_session.flush()

    claimed = lab_operations.claim_next(admin_session, claimed_by="worker")
    assert claimed is not None
    assert claimed.id == check.id
    admin_session.rollback()


def test_failed_destroy_keeps_instance_active_and_capacity_counted(admin_session, tenant_a):
    instance, _ = _seed(admin_session, tenant_a.id, status="active")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("destroy refused")

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=engine,
    ) == "failed"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert operation.state == "failed"
    assert "destroy refused" in operation.last_error


def test_failed_predeploy_destroy_is_capacity_counted_even_from_queued(
    admin_session, tenant_a
):
    instance, person = _seed(admin_session, tenant_a.id, name="predeploy-destroy")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("cannot prove old lab absent")

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=engine,
    ) == "failed"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert operation.state == "failed"
    assert "cannot prove old lab absent" in operation.last_error
    engine.deploy.assert_not_called()


def test_failed_reset_does_not_leave_a_closed_operation_in_resetting(
    admin_session, tenant_a, monkeypatch
):
    instance, person = _seed(
        admin_session, tenant_a.id, name="reset-transient", status="active"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    monkeypatch.setattr(
        lab_operations,
        "_run_deploy",
        MagicMock(side_effect=RuntimeError("pre-engine failure")),
    )

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    ) == "failed"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert instance.error == "pre-engine failure"
    assert operation.state == "failed"


def test_failed_check_rolls_back_a_partial_submission(
    admin_session, tenant_a, monkeypatch
):
    instance, person = _seed(
        admin_session, tenant_a.id, name="partial-check", status="active"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="check", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    def _partial_grade(db, checked_instance, *_args, **_kwargs):
        db.add(
            Submission(
                tenant_id=checked_instance.tenant_id,
                activity_id=checked_instance.activity_id,
                person_id=checked_instance.person_id,
                answers={"instance": str(checked_instance.id)},
                attempt_no=1,
            )
        )
        db.flush()
        raise RuntimeError("score write failed")

    monkeypatch.setattr(lab_operations.lab_lifecycle, "grade", _partial_grade)

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    ) == "failed"
    admin_session.refresh(operation)
    assert operation.state == "failed"
    assert "score write failed" in operation.last_error
    assert (
        admin_session.query(Submission)
        .filter(Submission.person_id == person.id)
        .count()
        == 0
    )


def test_error_retry_stays_queued_when_global_capacity_is_full(
    admin_session, tenant_a, monkeypatch
):
    active, _ = _seed(admin_session, tenant_a.id, name="active", status="active")
    retry, person = _seed(admin_session, tenant_a.id, name="retry", status="error")
    operation = lab_operations.enqueue(
        admin_session, instance=retry, kind="deploy", requested_by=person.id
    )
    admin_session.commit()

    claimed = lab_operations.claim_next(
        admin_session, claimed_by="worker", claimed_host="some-host", claimed_epoch="111:oldboot"
    )
    assert claimed is not None and claimed.id == operation.id
    admin_session.commit()
    admin_session.refresh(operation)
    assert operation.attempts == 1
    assert operation.claimed_host == "some-host"
    assert operation.claimed_epoch == "111:oldboot"

    monkeypatch.setattr(settings, "max_concurrent_labs", 1)
    engine = _engine(retry.instance_name)

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=engine,
    ) == "deferred"
    admin_session.refresh(retry)
    admin_session.refresh(operation)
    assert active.status == "active"
    assert retry.status == "queued"
    assert operation.state == "queued"
    assert operation.attempts == 0
    # Capacity deferral is a requeue path — the two structural claim-ownership
    # columns (migration 0059) must be cleared alongside claimed_by, exactly
    # like every other requeue path.
    assert operation.claimed_host is None
    assert operation.claimed_epoch is None
    engine.destroy.assert_not_called()
    engine.deploy.assert_not_called()


def test_absent_lab_allows_destroy_then_deploy_replay(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id)
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    engine = _engine(instance.instance_name)
    engine.destroy.return_value = None  # absent is already destroyed

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=engine,
    ) == "succeeded"
    admin_session.refresh(instance)
    assert instance.status == "active"
    engine.destroy.assert_called_once_with(instance.instance_name)
    engine.deploy.assert_called_once()


def test_expired_claim_is_requeued_and_stale_worker_cannot_settle(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id, status="provisioning")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "stale-worker"
    operation.claimed_host = "stale-host"
    operation.claimed_epoch = "111:staleboot"
    operation.claimed_at = datetime.now(UTC) - timedelta(minutes=20)
    operation.heartbeat_at = datetime.now(UTC) - timedelta(minutes=20)
    admin_session.commit()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    admin_session.commit()
    admin_session.refresh(operation)
    # Ordinary lease recovery is a requeue path too — the two structural
    # claim-ownership columns (migration 0059) must be cleared alongside
    # claimed_by, exactly like every other requeue path.
    assert operation.claimed_host is None
    assert operation.claimed_epoch is None
    replacement = lab_operations.claim_next(admin_session, claimed_by="new-worker")
    assert replacement is not None
    admin_session.commit()

    engine = _engine(instance.instance_name)
    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="stale-worker",
        engine=engine,
    ) == "stale"
    engine.destroy.assert_not_called()
    engine.deploy.assert_not_called()
    current = admin_session.scalar(select(LabOperation).where(LabOperation.id == operation.id))
    assert current is not None and current.claimed_by == "new-worker"


def test_threaded_admission_never_exceeds_global_capacity(
    admin_engine, admin_session, tenant_a, monkeypatch
):
    first_instance, first_person = _seed(admin_session, tenant_a.id, name="cap-one")
    second_instance, second_person = _seed(admin_session, tenant_a.id, name="cap-two")
    lab_operations.enqueue(
        admin_session,
        instance=first_instance,
        kind="deploy",
        requested_by=first_person.id,
    )
    lab_operations.enqueue(
        admin_session,
        instance=second_instance,
        kind="deploy",
        requested_by=second_person.id,
    )
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)

    start = Barrier(2)
    engines = [_engine(first_instance.instance_name), _engine(second_instance.instance_name)]
    factory = sessionmaker(bind=admin_engine, autoflush=False)

    def _worker(number: int) -> str:
        db = factory()
        try:
            operation = lab_operations.claim_next(db, claimed_by=f"worker-{number}")
            assert operation is not None
            operation_id = operation.id
            db.commit()
            start.wait(timeout=5)
            return lab_operations.run_claimed(
                db,
                operation_id=operation_id,
                claimed_by=f"worker-{number}",
                engine=engines[number],
            )
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_worker, (0, 1)))

    assert sorted(outcomes) == ["deferred", "succeeded"]
    admin_session.expire_all()
    statuses = admin_session.scalars(
        select(LabInstance.status).where(
            LabInstance.id.in_((first_instance.id, second_instance.id))
        )
    ).all()
    assert statuses.count("active") == 1
    assert statuses.count("queued") == 1
    assert sum(engine.deploy.call_count for engine in engines) == 1


def test_positive_per_tenant_limit_applies_inside_global_capacity(
    admin_session, tenant_a, monkeypatch
):
    active, _ = _seed(
        admin_session, tenant_a.id, name="tenant-active", status="active"
    )
    pending, person = _seed(admin_session, tenant_a.id, name="tenant-pending")
    operation = lab_operations.enqueue(
        admin_session, instance=pending, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = operation.claimed_at
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 2)
    monkeypatch.setattr(settings, "max_concurrent_labs_per_tenant", 1)
    engine = _engine(pending.instance_name)

    assert lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=engine,
    ) == "deferred"
    admin_session.refresh(pending)
    assert active.status == "active"
    assert pending.status == "queued"
    engine.destroy.assert_not_called()


def test_default_leases_are_longer_for_deploy_than_destroy(admin_session, tenant_a):
    deploy_instance, person = _seed(admin_session, tenant_a.id, name="deploy-lease")
    destroy_instance, _ = _seed(
        admin_session, tenant_a.id, name="destroy-lease", status="active"
    )
    old = datetime.now(UTC) - timedelta(seconds=700)
    deploy = lab_operations.enqueue(
        admin_session, instance=deploy_instance, kind="deploy", requested_by=person.id
    )
    destroy = lab_operations.enqueue(
        admin_session, instance=destroy_instance, kind="destroy", requested_by=None
    )
    for operation in (deploy, destroy):
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = old
        operation.heartbeat_at = old
    admin_session.flush()

    assert lab_operations.reconcile_stuck(admin_session) == 1
    assert deploy.state == "claimed"
    assert destroy.state == "queued"
    admin_session.rollback()


def test_expired_claim_stops_after_kind_attempt_ceiling(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id, name="attempt-ceiling")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC) - timedelta(hours=1)
    operation.heartbeat_at = operation.claimed_at
    operation.attempts = lab_operations.MAX_ATTEMPTS_BY_KIND["deploy"]
    admin_session.flush()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    assert operation.state == "failed"
    assert operation.finished_at is not None
    assert "after 3 attempts" in operation.last_error
    assert instance.status == "active"
    assert instance.error == operation.last_error
    admin_session.rollback()


def test_wrong_host_refusal_restores_state_and_refunds_attempt(
    admin_session, tenant_a, tmp_path, monkeypatch
):
    instance, person = _seed(admin_session, tenant_a.id, name="wrong-host")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = operation.claimed_at
    operation.attempts = 1
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 20)

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=ContainerlabEngine(str(tmp_path), lab_host_role="web"),
    )

    assert outcome == "failed"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "queued"
    assert instance.error is None
    assert operation.state == "failed"
    assert operation.attempts == 0


def test_worker_identity_includes_one_process_boot_token():
    identity = lab_operations.worker_identity()
    host, pid, token = identity.rsplit(":", 2)
    assert host
    assert pid.isdigit()
    assert len(token) == 8


def test_capacity_reservation_survives_worker_crash_before_settlement(
    admin_engine, admin_session, tenant_a, monkeypatch
):
    instance, person = _seed(admin_session, tenant_a.id, name="crash")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)
    engine = MagicMock()
    engine.destroy.side_effect = KeyboardInterrupt("simulated hard stop")

    try:
        lab_operations.run_claimed(
            admin_session,
            operation_id=operation.id,
            claimed_by="worker",
            engine=engine,
        )
    except KeyboardInterrupt:
        admin_session.rollback()

    factory = sessionmaker(bind=admin_engine, autoflush=False)
    check = factory()
    try:
        stored = check.get(LabInstance, instance.id)
        claim = check.get(LabOperation, operation.id)
        assert stored is not None and stored.status == "provisioning"
        assert claim is not None and claim.state == "claimed"
    finally:
        check.close()


def test_enqueue_retries_after_conflicting_operation_settles_mid_race(
    admin_session, tenant_a, monkeypatch
):
    """A conflicting insert whose row settles before the re-select must retry
    the whole insert exactly once instead of raising ``NoResultFound``."""
    instance, person = _seed(admin_session, tenant_a.id, name="race")
    existing = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    admin_session.flush()

    original_select = lab_operations._select_open_operation
    calls = {"n": 0}

    def _settle_conflict_then_select(db, inst):
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulate the conflicting operation settling out from under the
            # re-select: it leaves OPEN_STATES right here, so the retried
            # insert below observes no conflict and legitimately succeeds.
            settled = db.get(LabOperation, existing.id)
            settled.state = "succeeded"
            settled.finished_at = datetime.now(UTC)
            db.flush()
            return None
        return original_select(db, inst)

    monkeypatch.setattr(
        lab_operations, "_select_open_operation", _settle_conflict_then_select
    )

    retried = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )

    assert retried.id != existing.id
    assert retried.state == "queued"
    assert calls["n"] == 1  # the retried insert succeeded; no second re-select
    admin_session.rollback()


def test_enqueue_raises_conflict_error_when_retry_also_races(
    admin_session, tenant_a, monkeypatch
):
    """If the retried insert ALSO conflicts and the re-select ALSO finds
    nothing, enqueue must raise ConflictError rather than crash."""
    instance, person = _seed(admin_session, tenant_a.id, name="double-race")
    lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    admin_session.flush()

    # The real conflicting row is never settled, so both the initial insert
    # and the retried insert genuinely conflict; forcing the re-select to
    # always report "nothing found" reproduces the vanishingly-unlikely
    # double-vanish case deterministically.
    monkeypatch.setattr(
        lab_operations, "_select_open_operation", lambda db, inst: None
    )

    with pytest.raises(ConflictError):
        lab_operations.enqueue(
            admin_session, instance=instance, kind="deploy", requested_by=person.id
        )
    admin_session.rollback()


def test_five_consecutive_automatic_destroy_failures_escalate_instance_to_error(
    admin_session, tenant_a
):
    instance, _ = _seed(admin_session, tenant_a.id, name="escalate", status="active")
    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("destroy refused")

    for attempt in range(1, lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"] + 1):
        operation = lab_operations.enqueue(
            admin_session, instance=instance, kind="destroy", requested_by=None
        )
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = datetime.now(UTC)
        operation.heartbeat_at = datetime.now(UTC)
        operation.attempts = 1  # matches what claim_next() would have set
        admin_session.commit()

        outcome = lab_operations.run_claimed(
            admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
        )
        assert outcome == "failed"
        admin_session.refresh(instance)
        admin_session.refresh(operation)
        assert operation.state == "failed"
        if attempt < lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]:
            assert instance.status == "active"
        else:
            assert instance.status == "error"
            assert instance.error == (
                "automatic destroy failed 5 times; manual intervention required"
            )


def test_escalated_instance_stops_being_selected_by_idle_reaper(admin_session, tenant_a):
    instance, _ = _seed(
        admin_session, tenant_a.id, name="escalate-reaper", status="active"
    )
    instance.last_active_at = datetime.now(UTC) - timedelta(hours=2)
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("destroy refused")

    for _ in range(lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]):
        operation = lab_operations.enqueue(
            admin_session, instance=instance, kind="destroy", requested_by=None
        )
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = datetime.now(UTC)
        operation.heartbeat_at = datetime.now(UTC)
        operation.attempts = 1  # matches what claim_next() would have set
        admin_session.commit()
        lab_operations.run_claimed(
            admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
        )
    admin_session.refresh(instance)
    assert instance.status == "error"

    requested = lab_jobs.request_idle_reaps(admin_session)

    assert requested == 0
    admin_session.refresh(instance)
    assert (
        admin_session.query(LabOperation)
        .filter_by(instance_id=instance.id, state="queued")
        .count()
        == 0
    )


def test_user_initiated_deploy_survives_escalation_and_resets_failure_window(
    admin_session, tenant_a
):
    instance, person = _seed(
        admin_session, tenant_a.id, name="escalate-then-redeploy", status="active"
    )
    destroy_engine = MagicMock()
    destroy_engine.destroy.side_effect = RuntimeError("destroy refused")
    for _ in range(lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]):
        operation = lab_operations.enqueue(
            admin_session, instance=instance, kind="destroy", requested_by=None
        )
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = datetime.now(UTC)
        operation.heartbeat_at = datetime.now(UTC)
        operation.attempts = 1  # matches what claim_next() would have set
        admin_session.commit()
        lab_operations.run_claimed(
            admin_session,
            operation_id=operation.id,
            claimed_by="worker",
            engine=destroy_engine,
        )
    admin_session.refresh(instance)
    assert instance.status == "error"

    # (c) a user-attributed deploy can still be enqueued and completes even
    # after automatic-destroy escalation put the instance into "error".
    deploy_op = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    deploy_op.state = "claimed"
    deploy_op.claimed_by = "worker"
    deploy_op.claimed_at = datetime.now(UTC)
    deploy_op.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    deploy_outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=deploy_op.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    )
    assert deploy_outcome == "succeeded"
    admin_session.refresh(instance)
    assert instance.status == "active"
    assert instance.error is None

    # (d) a fresh first automatic destroy failure after that successful
    # redeploy must NOT immediately re-escalate: the failure-count window
    # reset by the successful deploy must be respected.
    post_redeploy_destroy = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    post_redeploy_destroy.state = "claimed"
    post_redeploy_destroy.claimed_by = "worker"
    post_redeploy_destroy.claimed_at = datetime.now(UTC)
    post_redeploy_destroy.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    second_destroy_engine = MagicMock()
    second_destroy_engine.destroy.side_effect = RuntimeError("destroy refused again")

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=post_redeploy_destroy.id,
        claimed_by="worker",
        engine=second_destroy_engine,
    )
    assert outcome == "failed"
    admin_session.refresh(instance)
    assert instance.status == "active"
    assert instance.error is None


def test_host_lock_contention_defers_without_charging_attempt_or_altering_state(
    admin_session, tenant_a
):
    instance, _ = _seed(admin_session, tenant_a.id, name="host-lock", status="active")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_host = "some-host"
    operation.claimed_epoch = "111:oldboot"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    operation.attempts = 1
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.side_effect = host_lock.HostLockUnavailable("host lock held")

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )

    assert outcome == "deferred"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert instance.error is None
    assert operation.state == "queued"
    assert operation.claimed_by is None
    # Host-lock contention is a requeue path — the two structural claim-
    # ownership columns (migration 0059) must be cleared alongside claimed_by,
    # exactly like every other requeue path.
    assert operation.claimed_host is None
    assert operation.claimed_epoch is None
    assert operation.attempts == 0


def test_deploy_failure_detected_even_when_provision_leaves_status_active(
    admin_session, tenant_a, monkeypatch
):
    """Stream B's ``provision`` may conservatively leave status "active" on a
    failed deploy; ``_run_deploy`` must still detect the failure via ``error``.
    """
    instance, person = _seed(admin_session, tenant_a.id, name="conservative-fail")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    def _conservative_failure(db, inst, engine, template):
        inst.status = "active"
        inst.error = "runtime creation began but deploy failed"
        db.flush()
        return inst

    monkeypatch.setattr(lab_operations.lab_lifecycle, "provision", _conservative_failure)

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    )

    assert outcome == "failed"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert instance.error == "runtime creation began but deploy failed"
    assert operation.state == "failed"
    assert "runtime creation began but deploy failed" in operation.last_error


def test_deploy_failure_after_proven_destroy_preserves_absent_presence(
    admin_session, tenant_a, monkeypatch
):
    """A pre-deploy-invocation failure inside provision() (topology prep)
    that follows a successful destroy proves the runtime absent. The generic
    failure handler in run_claimed must preserve that, not regress it to
    "unknown" and permanently strand a capacity slot.
    """
    instance, person = _seed(
        admin_session, tenant_a.id, name="destroyed-then-preflight-fail", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    def _proven_absent_failure(db, inst, engine, template):
        inst.status = "error"
        inst.error = "bad topology template"
        inst.runtime_presence = "absent"
        db.flush()
        return inst

    monkeypatch.setattr(lab_operations.lab_lifecycle, "provision", _proven_absent_failure)

    engine = _engine(instance.instance_name)  # destroy() has no side_effect, so it succeeds
    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=engine,
    )

    assert outcome == "failed"
    admin_session.refresh(instance)
    assert instance.status == "error"
    assert instance.runtime_presence == "absent"
    engine.deploy.assert_not_called()

    # And: the now-proven-absent instance must not still consume capacity —
    # another tenant instance should be admissible even at a cap of 1.
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)
    another, _ = _seed(admin_session, tenant_a.id, name="another", presence="absent")
    assert lab_operations._capacity_available(admin_session, another) is True


def test_wrong_host_refusals_do_not_contribute_to_destroy_escalation_count(
    admin_session, tenant_a, tmp_path
):
    """WrongLabHostError refusals are operator/placement misconfiguration, not
    genuine destroy execution failures, and must not count toward the
    cumulative automatic-destroy escalation threshold."""
    instance, _ = _seed(
        admin_session, tenant_a.id, name="wrong-host-destroy", status="active"
    )
    refusing_engine = ContainerlabEngine(str(tmp_path), lab_host_role="web")
    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]

    for _ in range(threshold + 2):
        operation = lab_operations.enqueue(
            admin_session, instance=instance, kind="destroy", requested_by=None
        )
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = datetime.now(UTC)
        operation.heartbeat_at = datetime.now(UTC)
        admin_session.commit()

        outcome = lab_operations.run_claimed(
            admin_session,
            operation_id=operation.id,
            claimed_by="worker",
            engine=refusing_engine,
        )
        assert outcome == "failed"

    admin_session.refresh(instance)
    assert instance.status == "active"
    assert instance.error is None


def test_legacy_unmarked_wrong_host_rows_do_not_contribute_to_escalation_count(
    admin_session, tenant_a
):
    """A row that failed via WrongLabHostError before the operator-refusal
    marker existed (bare ``str(exc)``, no ``[operator-refusal]`` prefix — the
    shape base PR #148 code would have written) must still be excluded from
    the cumulative escalation count, via the stable WrongLabHostError message
    substring rather than the marker alone."""
    instance, _ = _seed(
        admin_session, tenant_a.id, name="legacy-wrong-host", status="active"
    )
    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]

    for _ in range(threshold - 1):
        legacy_operation = lab_operations.enqueue(
            admin_session, instance=instance, kind="destroy", requested_by=None
        )
        legacy_operation.state = "failed"
        legacy_operation.finished_at = datetime.now(UTC)
        legacy_operation.last_error = (
            "containerlab operations require LAB_HOST_ROLE=lab (got 'web')"
        )
        admin_session.commit()

    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("destroy refused")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    # If the legacy rows above wrongly counted, this single genuine failure
    # would be the (threshold-1)+1'th and would escalate; the fix keeps it at
    # count 1 since none of the legacy wrong-host rows are genuine failures.
    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )

    assert outcome == "failed"
    admin_session.refresh(instance)
    assert instance.status == "active"
    assert instance.error is None


def test_stuck_destroy_claim_escalates_instance_via_reconcile_stuck(
    admin_session, tenant_a
):
    """A destroy that exhausts its attempts via lease expiry (worker
    crash/hang), not a synchronous exception, must escalate the same way a
    synchronously-failing destroy does — otherwise a hanging engine lets the
    idle reaper re-enqueue destroys for this instance forever."""
    instance, _ = _seed(
        admin_session, tenant_a.id, name="stuck-destroy-escalate", status="active"
    )
    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]
    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("destroy refused")

    for _ in range(threshold - 1):
        operation = lab_operations.enqueue(
            admin_session, instance=instance, kind="destroy", requested_by=None
        )
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = datetime.now(UTC)
        operation.heartbeat_at = datetime.now(UTC)
        admin_session.commit()
        lab_operations.run_claimed(
            admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
        )
    admin_session.refresh(instance)
    assert instance.status == "active"

    stuck_operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    stuck_operation.state = "claimed"
    stuck_operation.claimed_by = "stale-worker"
    stuck_operation.claimed_at = datetime.now(UTC) - timedelta(hours=1)
    stuck_operation.heartbeat_at = datetime.now(UTC) - timedelta(hours=1)
    stuck_operation.attempts = threshold
    admin_session.commit()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    admin_session.refresh(instance)
    admin_session.refresh(stuck_operation)
    assert stuck_operation.state == "failed"
    assert instance.status == "error"
    assert instance.error == (
        f"automatic destroy failed {threshold} times; manual intervention required"
    )


def test_single_stuck_destroy_row_escalates_via_reconcile_stuck_alone(
    admin_session, tenant_a
):
    """Escalation sums attempts, not distinct failed rows: a single operation
    that hangs and burns its full attempt budget via repeated lease-expiry/
    reclaim cycles on the SAME row already represents a full attempt budget
    and must escalate on its own, with no other prior failed rows needed."""
    instance, _ = _seed(
        admin_session, tenant_a.id, name="single-row-escalate", status="active"
    )
    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]

    stuck_operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    stuck_operation.state = "claimed"
    stuck_operation.claimed_by = "stale-worker"
    stuck_operation.claimed_at = datetime.now(UTC) - timedelta(hours=1)
    stuck_operation.heartbeat_at = datetime.now(UTC) - timedelta(hours=1)
    stuck_operation.attempts = threshold
    admin_session.commit()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    admin_session.refresh(instance)
    admin_session.refresh(stuck_operation)
    assert stuck_operation.state == "failed"
    assert instance.status == "error"
    assert instance.error == (
        f"automatic destroy failed {threshold} times; manual intervention required"
    )


def test_host_lock_during_redeploy_provision_does_not_falsely_restore_active(
    admin_session, tenant_a, monkeypatch
):
    """If the destroy half of a deploy's destroy-then-provision sequence
    already succeeded (the real runtime is torn down) and it is the
    subsequent provision/deploy call that hits HostLockUnavailable, restoring
    the pre-op "active" status would falsely claim a working lab. The
    instance must stay in the mid-flight "resetting"/"provisioning" state
    _run_deploy already left it in."""
    instance, person = _seed(
        admin_session, tenant_a.id, name="host-lock-redeploy", status="active"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    operation.attempts = 1
    admin_session.commit()

    engine = MagicMock()
    engine.destroy.return_value = None  # the old runtime is genuinely torn down

    def _provision_hits_host_lock(db, inst, eng, template):
        raise host_lock.HostLockUnavailable("host lock held during redeploy")

    monkeypatch.setattr(
        lab_operations.lab_lifecycle, "provision", _provision_hits_host_lock
    )

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )

    assert outcome == "deferred"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "resetting"
    assert operation.state == "queued"
    assert operation.claimed_by is None
    assert operation.attempts == 0


# --- runtime_presence: capacity accounting ----------------------------------


def test_present_presence_consumes_capacity_regardless_of_lifecycle_status(
    admin_session, tenant_a, monkeypatch
):
    """An "error" instance whose presence is "present" must still be counted
    against global capacity — capacity is keyed off runtime_presence, not
    lifecycle status."""
    present_but_errored, _ = _seed(
        admin_session, tenant_a.id, name="present-error", status="error", presence="present"
    )
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)

    fresh, person = _seed(admin_session, tenant_a.id, name="present-blocked")
    operation = lab_operations.enqueue(
        admin_session, instance=fresh, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = operation.claimed_at
    admin_session.commit()

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(fresh.instance_name),
    )
    assert outcome == "deferred"
    admin_session.refresh(fresh)
    assert fresh.status == "queued"
    admin_session.refresh(present_but_errored)
    assert present_but_errored.runtime_presence == "present"


def test_unknown_presence_consumes_capacity_regardless_of_lifecycle_status(
    admin_session, tenant_a, monkeypatch
):
    """A "queued" instance whose presence is "unknown" (e.g. a pre-cutover
    repair row) must still be counted against global capacity."""
    unknown_but_queued, _ = _seed(
        admin_session, tenant_a.id, name="unknown-queued", status="queued", presence="unknown"
    )
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)

    fresh, person = _seed(admin_session, tenant_a.id, name="unknown-blocked")
    operation = lab_operations.enqueue(
        admin_session, instance=fresh, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = operation.claimed_at
    admin_session.commit()

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(fresh.instance_name),
    )
    assert outcome == "deferred"
    admin_session.refresh(fresh)
    assert fresh.status == "queued"


def test_absent_presence_does_not_consume_capacity(admin_session, tenant_a, monkeypatch):
    """An "active"-status instance whose presence is "absent" (contradictory
    in practice, but proves the accounting is presence-keyed) must NOT count
    against the cap."""
    active_but_absent, _ = _seed(
        admin_session, tenant_a.id, name="active-absent", status="active", presence="absent"
    )
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)

    fresh, person = _seed(admin_session, tenant_a.id, name="absent-not-blocked")
    operation = lab_operations.enqueue(
        admin_session, instance=fresh, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = operation.claimed_at
    admin_session.commit()

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(fresh.instance_name),
    )
    assert outcome == "succeeded"
    admin_session.refresh(fresh)
    assert fresh.status == "active"
    admin_session.refresh(active_but_absent)
    assert active_but_absent.runtime_presence == "absent"  # untouched by this pass


def test_capacity_deferral_preserves_presence(admin_session, tenant_a, monkeypatch):
    """A deferred admission (capacity full) must not mutate the deferred
    instance's presence — only its status/operation are requeued.

    The deferred candidate must genuinely NOT already be capacity-counted
    (presence="absent"): `_capacity_available`'s `already_consuming` check
    treats "present"/"unknown" as already-counted-so-admit-regardless-of-cap,
    so seeding this instance with either of those values would make it
    ineligible for deferral in the first place, contradicting the very
    scenario this test means to exercise.
    """
    blocker, _ = _seed(admin_session, tenant_a.id, name="deferral-blocker", status="active")
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)

    retry, person = _seed(
        admin_session, tenant_a.id, name="deferral-retry", status="error", presence="absent"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=retry, kind="deploy", requested_by=person.id
    )
    admin_session.commit()
    claimed = lab_operations.claim_next(admin_session, claimed_by="worker")
    assert claimed is not None and claimed.id == operation.id
    admin_session.commit()

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=_engine(retry.instance_name)
    )
    assert outcome == "deferred"
    admin_session.refresh(retry)
    assert retry.status == "queued"
    assert retry.runtime_presence == "absent"  # untouched — never became capacity-counted


def test_already_consuming_presence_is_admitted_even_when_cap_is_full(
    admin_session, tenant_a, monkeypatch
):
    """The inverse of the deferral test above: an instance whose OWN presence
    is already "present"/"unknown" is the `already_consuming` short-circuit's
    actual job to admit regardless of the cap — it is already occupying a
    capacity slot, so refusing it would not free any capacity, only stall a
    redeploy of an instance that's already counted."""
    for presence in ("present", "unknown"):
        blocker, _ = _seed(
            admin_session, tenant_a.id, name=f"already-consuming-blocker-{presence}", status="active"
        )
        admin_session.commit()
        monkeypatch.setattr(settings, "max_concurrent_labs", 1)

        candidate, person = _seed(
            admin_session,
            tenant_a.id,
            name=f"already-consuming-{presence}",
            status="active",
            presence=presence,
        )
        operation = lab_operations.enqueue(
            admin_session, instance=candidate, kind="deploy", requested_by=person.id
        )
        operation.state = "claimed"
        operation.claimed_by = "worker"
        operation.claimed_at = datetime.now(UTC)
        operation.heartbeat_at = operation.claimed_at
        admin_session.commit()

        outcome = lab_operations.run_claimed(
            admin_session,
            operation_id=operation.id,
            claimed_by="worker",
            engine=_engine(candidate.instance_name),
        )
        # The global cap (1) is already fully occupied by `blocker` alone —
        # admission only succeeds because `candidate` was already counted.
        assert outcome == "succeeded", (
            f"presence={presence!r} candidate should be admitted regardless of "
            "the cap via the already_consuming short-circuit"
        )


def test_deploy_reservation_sets_unknown_before_external_work(
    admin_engine, admin_session, tenant_a, monkeypatch
):
    """The durable deploy reservation (committed before slow external work)
    must set presence to "unknown" in the same commit — a crash right after
    must leave "unknown" durably visible to another session."""
    instance, person = _seed(admin_session, tenant_a.id, name="reservation-crash")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 1)
    engine = MagicMock()
    engine.destroy.side_effect = KeyboardInterrupt("simulated hard stop")

    try:
        lab_operations.run_claimed(
            admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
        )
    except KeyboardInterrupt:
        admin_session.rollback()

    factory = sessionmaker(bind=admin_engine, autoflush=False)
    check = factory()
    try:
        stored = check.get(LabInstance, instance.id)
        assert stored is not None
        assert stored.runtime_presence == "unknown"
    finally:
        check.close()


def test_failed_deploy_persists_unknown_presence(admin_session, tenant_a, monkeypatch):
    instance, person = _seed(admin_session, tenant_a.id, name="deploy-fail-presence")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    def _conservative_failure(db, inst, engine, template):
        inst.status = "active"
        inst.error = "deploy failed"
        db.flush()
        return inst

    monkeypatch.setattr(lab_operations.lab_lifecycle, "provision", _conservative_failure)

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    )
    assert outcome == "failed"
    admin_session.refresh(instance)
    assert instance.runtime_presence == "unknown"


def test_failed_destroy_persists_unknown_presence_manual(admin_session, tenant_a):
    """A manual (user requested_by) destroy failure also sets "unknown" —
    the presence assignment is unconditional on requested_by, unlike the
    escalation check."""
    instance, person = _seed(admin_session, tenant_a.id, name="manual-destroy-fail", status="active")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.side_effect = RuntimeError("destroy refused")

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )
    assert outcome == "failed"
    admin_session.refresh(instance)
    assert instance.runtime_presence == "unknown"
    assert instance.status == "active"  # manual failures are never escalated


def test_wrong_host_refusal_restores_initial_presence(
    admin_session, tenant_a, tmp_path, monkeypatch
):
    instance, person = _seed(
        admin_session, tenant_a.id, name="wrong-host-presence", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = operation.claimed_at
    operation.attempts = 1
    admin_session.commit()
    monkeypatch.setattr(settings, "max_concurrent_labs", 20)

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=ContainerlabEngine(str(tmp_path), lab_host_role="web"),
    )

    assert outcome == "failed"
    admin_session.refresh(instance)
    assert instance.runtime_presence == "present"


def test_host_lock_non_deploy_restores_initial_presence(admin_session, tenant_a):
    instance, _ = _seed(
        admin_session, tenant_a.id, name="host-lock-presence", status="active", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    operation.attempts = 1
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.side_effect = host_lock.HostLockUnavailable("host lock held")

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )
    assert outcome == "deferred"
    admin_session.refresh(instance)
    assert instance.runtime_presence == "present"


def test_host_lock_post_destroy_deploy_retains_unknown(
    admin_session, tenant_a, monkeypatch
):
    """Host-lock contention hit AFTER the destroy half of a deploy already
    succeeded must retain "unknown", not restore the pre-op presence — the
    old runtime may genuinely be gone."""
    instance, person = _seed(
        admin_session, tenant_a.id, name="host-lock-deploy-presence", status="active", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    operation.attempts = 1
    admin_session.commit()

    engine = MagicMock()
    engine.destroy.return_value = None  # the old runtime is genuinely torn down

    def _provision_hits_host_lock(db, inst, eng, template):
        raise host_lock.HostLockUnavailable("host lock held during redeploy")

    monkeypatch.setattr(lab_operations.lab_lifecycle, "provision", _provision_hits_host_lock)

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )

    assert outcome == "deferred"
    admin_session.refresh(instance)
    assert instance.runtime_presence == "unknown"


def test_lease_expiry_over_ceiling_retains_unknown(admin_session, tenant_a):
    instance, person = _seed(
        admin_session, tenant_a.id, name="lease-ceiling-presence", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC) - timedelta(hours=1)
    operation.heartbeat_at = operation.claimed_at
    operation.attempts = lab_operations.MAX_ATTEMPTS_BY_KIND["deploy"]
    admin_session.flush()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    assert instance.runtime_presence == "unknown"
    admin_session.rollback()


def test_lease_expiry_under_ceiling_sets_unknown_on_requeue(admin_session, tenant_a):
    instance, person = _seed(
        admin_session, tenant_a.id, name="lease-requeue-presence", status="provisioning", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC) - timedelta(minutes=20)
    operation.heartbeat_at = operation.claimed_at
    admin_session.commit()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    admin_session.refresh(instance)
    assert instance.status == "queued"
    assert instance.runtime_presence == "unknown"


def test_stuck_destroy_escalation_retains_unknown(admin_session, tenant_a):
    instance, _ = _seed(
        admin_session, tenant_a.id, name="stuck-destroy-presence", status="active", presence="present"
    )
    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]
    stuck_operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    stuck_operation.state = "claimed"
    stuck_operation.claimed_by = "stale-worker"
    stuck_operation.claimed_at = datetime.now(UTC) - timedelta(hours=1)
    stuck_operation.heartbeat_at = stuck_operation.claimed_at
    stuck_operation.attempts = threshold
    admin_session.commit()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    admin_session.refresh(instance)
    assert instance.status == "error"
    assert instance.runtime_presence == "unknown"  # escalation never forces "absent"


def test_successful_deploy_becomes_present(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id, name="deploy-success-presence")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    )
    assert outcome == "succeeded"
    admin_session.refresh(instance)
    assert instance.runtime_presence == "present"


def test_successful_destroy_becomes_absent(admin_session, tenant_a):
    instance, _ = _seed(
        admin_session, tenant_a.id, name="destroy-success-presence", status="active", presence="present"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    operation.state = "claimed"
    operation.claimed_by = "worker"
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    admin_session.commit()
    engine = MagicMock()
    engine.destroy.return_value = None

    outcome = lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine
    )
    assert outcome == "succeeded"
    admin_session.refresh(instance)
    assert instance.status == "reaped"
    assert instance.runtime_presence == "absent"


# --- Stage 2: structural claim ownership and restart reclaim ---------------


def test_claim_next_persists_structural_ownership_alongside_unchanged_claimed_by(
    admin_session, tenant_a
):
    """``claimed_by`` stays byte-for-byte what ``worker_identity()`` already
    produces; ``claimed_host``/``claimed_epoch`` are persisted alongside it
    from the same ``WorkerIdentity``."""
    instance, person = _seed(admin_session, tenant_a.id, name="claim-persist")
    lab_operations.enqueue(admin_session, instance=instance, kind="deploy", requested_by=person.id)
    admin_session.commit()

    identity = lab_operations.worker_identity_parts()
    claimed = lab_operations.claim_next(
        admin_session,
        claimed_by=identity.claimed_by,
        claimed_host=identity.host,
        claimed_epoch=identity.epoch,
    )
    assert claimed is not None
    assert claimed.claimed_by == lab_operations.worker_identity()
    assert claimed.claimed_host == identity.host
    assert claimed.claimed_epoch == identity.epoch
    admin_session.rollback()


def _claim_row(op, *, claimed_by, claimed_host, claimed_epoch, age=None):
    age = age or timedelta(seconds=0)
    op.state = "claimed"
    op.claimed_by = claimed_by
    op.claimed_host = claimed_host
    op.claimed_epoch = claimed_epoch
    op.claimed_at = datetime.now(UTC) - age
    op.heartbeat_at = datetime.now(UTC) - age


def test_reclaim_previous_epoch_reclaims_same_host_different_epoch_claim(
    admin_session, tenant_a
):
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-basic", status="provisioning")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation, claimed_by="host-a:111:oldboot", claimed_host="host-a", claimed_epoch="111:oldboot"
    )
    operation.attempts = 1
    admin_session.commit()

    reclaimed = lab_operations.reclaim_previous_epoch(
        admin_session, host="host-a", epoch="222:newboot"
    )
    admin_session.commit()

    assert reclaimed == 1
    admin_session.refresh(operation)
    assert operation.state == "queued"
    assert operation.claimed_by is None
    assert operation.claimed_host is None
    assert operation.claimed_epoch is None
    assert operation.claimed_at is None
    assert operation.heartbeat_at is None
    # No refund: attempts stays exactly what claim_next set it to, identical
    # to reconcile_stuck's own under-ceiling requeue.
    assert operation.attempts == 1
    assert "restart reclaim" in operation.last_error
    assert "111:oldboot" in operation.last_error
    assert "222:newboot" in operation.last_error
    assert "host-a" in operation.last_error

    admin_session.refresh(instance)
    assert instance.status == "queued"  # provisioning -> queued, same as reconcile_stuck
    assert instance.runtime_presence == "unknown"


def test_reclaim_previous_epoch_projects_resetting_to_active_for_destroy(
    admin_session, tenant_a
):
    instance, _ = _seed(
        admin_session, tenant_a.id, name="reclaim-resetting", status="resetting", presence="unknown"
    )
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    _claim_row(
        operation, claimed_by="host-a:111:oldboot", claimed_host="host-a", claimed_epoch="111:oldboot"
    )
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 1
    )
    admin_session.commit()
    admin_session.refresh(instance)
    assert instance.status == "active"
    assert instance.runtime_presence == "unknown"


def test_reclaim_previous_epoch_leaves_current_epoch_claim_untouched(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-current-epoch")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation, claimed_by="host-a:333:thisboot", claimed_host="host-a", claimed_epoch="333:thisboot"
    )
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="333:thisboot")
        == 0
    )
    admin_session.refresh(operation)
    assert operation.state == "claimed"
    assert operation.claimed_by == "host-a:333:thisboot"
    assert operation.claimed_host == "host-a"
    assert operation.claimed_epoch == "333:thisboot"
    admin_session.rollback()


def test_reclaim_previous_epoch_leaves_different_host_claim_untouched(admin_session, tenant_a):
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-other-host")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation, claimed_by="host-b:111:oldboot", claimed_host="host-b", claimed_epoch="111:oldboot"
    )
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 0
    )
    admin_session.refresh(operation)
    assert operation.state == "claimed"
    assert operation.claimed_host == "host-b"
    admin_session.rollback()


def test_reclaim_previous_epoch_leaves_legacy_null_ownership_claim_untouched(
    admin_session, tenant_a
):
    """A row claimed by a pre-0059 worker (or a caller that never supplied
    structural ownership) has null ``claimed_host``/``claimed_epoch`` and must
    remain lease-expiry-only — exactly as before this function existed."""
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-legacy")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(operation, claimed_by="host-a:111:oldboot", claimed_host=None, claimed_epoch=None)
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 0
    )
    admin_session.refresh(operation)
    assert operation.state == "claimed"
    assert operation.claimed_by == "host-a:111:oldboot"
    admin_session.rollback()


def test_reclaim_previous_epoch_does_not_refund_an_attempt(admin_session, tenant_a):
    """An under-ceiling restart reclaim must leave ``attempts`` exactly as
    ``claim_next`` last set it — no refund — identical to
    ``reconcile_stuck``'s own under-ceiling requeue. A refund here would let a
    worker that repeatedly crashes before ever settling the same row cycle
    claim (+1) then reclaim (-1) forever without ``attempts`` ever
    net-advancing, silently defeating ``MAX_ATTEMPTS_BY_KIND`` for exactly the
    failure mode restart-reclaim exists to handle."""
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-zero-floor")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation, claimed_by="host-a:111:oldboot", claimed_host="host-a", claimed_epoch="111:oldboot"
    )
    operation.attempts = 0
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 1
    )
    admin_session.refresh(operation)
    assert operation.attempts == 0  # unchanged, not decremented below zero

    other_instance, other_person = _seed(admin_session, tenant_a.id, name="reclaim-nonzero")
    other_operation = lab_operations.enqueue(
        admin_session, instance=other_instance, kind="deploy", requested_by=other_person.id
    )
    _claim_row(
        other_operation,
        claimed_by="host-a:333:oldboot2",
        claimed_host="host-a",
        claimed_epoch="333:oldboot2",
    )
    other_operation.attempts = 2
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="444:newboot2")
        == 1
    )
    admin_session.refresh(other_operation)
    assert other_operation.attempts == 2  # unchanged, not decremented


def test_repeated_crash_before_settling_accumulates_to_ceiling_not_forgiven(
    admin_session, tenant_a
):
    """A worker that repeatedly crashes before ever settling the SAME
    operation must have its attempts accumulate toward the kind's ceiling
    across restarts, exactly like an ordinary repeated lease-timeout would —
    not be unconditionally forgiven by a refund on every restart-reclaim.
    Cycles claim_next -> commit -> reclaim_previous_epoch -> commit through
    the full attempt ceiling and asserts the operation lands "failed" with
    attempts at the ceiling, instead of oscillating between 0 and 1 forever."""
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-crash-loop")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    admin_session.commit()

    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["deploy"]
    for cycle in range(threshold):
        old_epoch = f"{cycle}:oldboot"
        new_epoch = f"{cycle + 1}:newboot"
        claimed = lab_operations.claim_next(
            admin_session,
            claimed_by=f"host-a:{old_epoch}",
            claimed_host="host-a",
            claimed_epoch=old_epoch,
        )
        assert claimed is not None and claimed.id == operation.id
        admin_session.commit()

        reclaimed = lab_operations.reclaim_previous_epoch(
            admin_session, host="host-a", epoch=new_epoch
        )
        admin_session.commit()
        assert reclaimed == 1

    admin_session.refresh(operation)
    assert operation.state == "failed"
    assert operation.attempts == threshold
    assert "attempt ceiling" in operation.last_error

    # The row is settled terminal — no further claim is possible.
    assert lab_operations.claim_next(admin_session, claimed_by="host-a:should-not-claim") is None


def test_reclaim_previous_epoch_rollback_leaves_original_claim_intact(admin_session, tenant_a):
    """Simulates an interrupted reclaim transaction (e.g. a SIGTERM arriving
    mid-reclaim): if the caller rolls back instead of committing, the
    original claim must be left completely intact — not partially modified.
    """
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-rollback")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation, claimed_by="host-a:111:oldboot", claimed_host="host-a", claimed_epoch="111:oldboot"
    )
    operation.attempts = 1
    admin_session.commit()
    operation_id = operation.id

    reclaimed = lab_operations.reclaim_previous_epoch(
        admin_session, host="host-a", epoch="222:newboot"
    )
    assert reclaimed == 1
    admin_session.rollback()

    current = admin_session.scalar(select(LabOperation).where(LabOperation.id == operation_id))
    assert current.state == "claimed"
    assert current.claimed_by == "host-a:111:oldboot"
    assert current.claimed_host == "host-a"
    assert current.claimed_epoch == "111:oldboot"
    assert current.attempts == 1
    assert current.last_error is None


def test_reclaimed_old_claimed_by_cannot_heartbeat_or_settle_after_a_new_claim(
    admin_session, tenant_a
):
    """After restart reclaim requeues a row and a new worker claims it, the
    OLD ``claimed_by`` must be rejected by the existing exact-string fence
    alone — a regression test proving structural fields were never needed in
    that fence, and it still works unchanged."""
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-fence", status="provisioning")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    old_claimed_by = "host-a:111:oldboot"
    _claim_row(operation, claimed_by=old_claimed_by, claimed_host="host-a", claimed_epoch="111:oldboot")
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 1
    )
    admin_session.commit()

    new_claimed_by = "host-a:222:newboot"
    new_claim = lab_operations.claim_next(
        admin_session,
        claimed_by=new_claimed_by,
        claimed_host="host-a",
        claimed_epoch="222:newboot",
    )
    assert new_claim is not None and new_claim.id == operation.id
    admin_session.commit()

    assert (
        lab_operations.heartbeat(admin_session, operation_id=operation.id, claimed_by=old_claimed_by)
        is False
    )
    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by=old_claimed_by,
        engine=_engine(instance.instance_name),
    )
    assert outcome == "stale"


def test_structural_ownership_fields_play_no_part_in_any_fencing_predicate(
    admin_session, tenant_a
):
    """``claimed_host``/``claimed_epoch`` are informational only — every
    fencing predicate (``heartbeat``, ``_refresh_claim``/``run_claimed``,
    ``_settle``) compares ``claimed_by`` alone. A deliberately mismatched/
    garbage pair of structural fields must not affect whether a claim's real
    owner can heartbeat or settle it — planting a defect that added either
    field to a fencing predicate's WHERE clause would make this fail."""
    instance, person = _seed(admin_session, tenant_a.id, name="fencing-guard")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation,
        claimed_by="worker",
        claimed_host="deliberately-wrong-host",
        claimed_epoch="deliberately-wrong-epoch",
    )
    admin_session.commit()

    assert (
        lab_operations.heartbeat(admin_session, operation_id=operation.id, claimed_by="worker")
        is True
    )

    outcome = lab_operations.run_claimed(
        admin_session,
        operation_id=operation.id,
        claimed_by="worker",
        engine=_engine(instance.instance_name),
    )
    assert outcome == "succeeded"


# --- reclaim_previous_epoch: attempt-ceiling and lock-wait hardening --------


def test_reclaim_previous_epoch_stops_after_kind_attempt_ceiling(admin_session, tenant_a):
    """A restart-reclaimed row already at its kind's attempt ceiling must be
    marked "failed", not requeued with a refunded attempt — otherwise a
    worker process that repeatedly crashes before ever settling this same
    claim would unconditionally refund the attempt `claim_next` charged on
    every restart, silently defeating `MAX_ATTEMPTS_BY_KIND` forever. Mirrors
    `test_expired_claim_stops_after_kind_attempt_ceiling`'s assertions for the
    `reconcile_stuck` path, adapted for `reclaim_previous_epoch`."""
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-ceiling")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation,
        claimed_by="host-a:111:oldboot",
        claimed_host="host-a",
        claimed_epoch="111:oldboot",
    )
    operation.attempts = lab_operations.MAX_ATTEMPTS_BY_KIND["deploy"]
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 1
    )
    admin_session.commit()
    admin_session.refresh(operation)
    admin_session.refresh(instance)

    assert operation.state == "failed"
    assert operation.finished_at is not None
    # Not refunded: an at-ceiling row must never get its attempt back.
    assert operation.attempts == lab_operations.MAX_ATTEMPTS_BY_KIND["deploy"]
    assert "attempt ceiling" in operation.last_error
    # Terminal settlement retains claim fields as audit provenance, exactly
    # like reconcile_stuck's own ceiling branch — never cleared here.
    assert operation.claimed_by == "host-a:111:oldboot"
    assert operation.claimed_host == "host-a"
    assert operation.claimed_epoch == "111:oldboot"

    assert instance.status == "active"
    assert instance.error == operation.last_error
    assert instance.runtime_presence == "unknown"


def test_reclaim_previous_epoch_escalates_automatic_destroy_at_ceiling(
    admin_session, tenant_a
):
    """An automatic (`requested_by=None`) destroy already at the destroy
    attempt ceiling, when matched by a restart-reclaim scan, must trigger the
    same escalation-to-"error" path `reconcile_stuck`'s own ceiling branch
    already applies — a crashing worker must not be able to dodge escalation
    just because it never lived long enough to hit `reconcile_stuck`'s
    lease-expiry check first. Mirrors
    `test_single_stuck_destroy_row_escalates_via_reconcile_stuck_alone`."""
    instance, _ = _seed(
        admin_session, tenant_a.id, name="reclaim-escalate", status="active"
    )
    threshold = lab_operations.MAX_ATTEMPTS_BY_KIND["destroy"]
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="destroy", requested_by=None
    )
    _claim_row(
        operation,
        claimed_by="host-a:111:oldboot",
        claimed_host="host-a",
        claimed_epoch="111:oldboot",
    )
    operation.attempts = threshold
    admin_session.commit()

    assert (
        lab_operations.reclaim_previous_epoch(admin_session, host="host-a", epoch="222:newboot")
        == 1
    )
    admin_session.commit()
    admin_session.refresh(operation)
    admin_session.refresh(instance)

    assert operation.state == "failed"
    assert operation.attempts == threshold  # not refunded
    assert instance.status == "error"
    assert instance.error == (
        f"automatic destroy failed {threshold} times; manual intervention required"
    )
    assert instance.runtime_presence == "unknown"


def test_reclaim_previous_epoch_lock_wait_is_bounded_by_lock_timeout(
    admin_engine, admin_session, tenant_a
):
    """`reclaim_previous_epoch`'s blocking (deliberately non-`SKIP LOCKED`)
    `FOR UPDATE` scan must not be able to hang the whole worker's startup
    indefinitely: a `lock_timeout` set on its own transaction bounds the
    wait, so a real conflicting row lock held open by another transaction
    (e.g. the separate `lab-reconcile` process, which is not covered by this
    worker's own singleton lock) makes this call raise within seconds instead
    of blocking forever."""
    instance, person = _seed(admin_session, tenant_a.id, name="reclaim-lock-timeout")
    operation = lab_operations.enqueue(
        admin_session, instance=instance, kind="deploy", requested_by=person.id
    )
    _claim_row(
        operation,
        claimed_by="host-a:111:oldboot",
        claimed_host="host-a",
        claimed_epoch="111:oldboot",
    )
    admin_session.commit()

    factory = sessionmaker(bind=admin_engine, autoflush=False)
    holder = factory()
    # Take and deliberately hold a real conflicting row lock in a separate
    # session/connection — left open (no commit/rollback) across the
    # assertion below, simulating another transaction contending for the
    # exact row reclaim_previous_epoch's FOR UPDATE will try to lock.
    holder.execute(
        select(LabOperation).where(LabOperation.id == operation.id).with_for_update()
    )
    try:
        start = time.monotonic()
        with pytest.raises(OperationalError):
            lab_operations.reclaim_previous_epoch(
                admin_session, host="host-a", epoch="222:newboot"
            )
        elapsed = time.monotonic() - start
        # Comfortably above the 5s lock_timeout, nowhere near "forever" —
        # proves the wait is bounded rather than merely "usually fast".
        assert elapsed < 10
    finally:
        admin_session.rollback()
        holder.rollback()
        holder.close()


# --- Conditional operations (migration 0060_lab_conditional_ops) -----------


def _claim(db, operation, *, claimed_by="worker"):
    """Claim ``operation`` by hand, mirroring ``claim_next``'s attempt charge
    (``op.attempts += 1``) so a HostLockUnavailable-triggered refund is
    actually observable (from a nonzero starting value), not trivially
    "0 minus 1, floored back to 0" either way."""
    operation.state = "claimed"
    operation.claimed_by = claimed_by
    operation.claimed_at = datetime.now(UTC)
    operation.heartbeat_at = datetime.now(UTC)
    operation.attempts += 1
    db.commit()


def test_conditional_deploy_crash_then_reclaim_then_retry_resyncs_consoles_and_status(
    admin_session, tenant_a
):
    """Reproduces the exact crash-then-retry gap: a conditional deploy's
    ``deploy_if_absent()`` genuinely succeeds, but the worker process crashes
    before ``provision_if_absent`` ever records ``consoles``/``status``.
    ``reclaim_previous_epoch`` requeues the still-``claimed`` row (projecting
    a defensive, stale ``status``/``runtime_presence`` it has no way to know
    is wrong). A second worker then claims the SAME operation; its
    preliminary check correctly observes the runtime IS present (it really
    was deployed). Without the resync fix, this would settle "succeeded"
    with empty ``consoles`` and a stale, non-"active" ``status`` — a live,
    running lab that looks like nothing happened. With the fix, the
    preliminary-present path detects the empty ``consoles`` and performs a
    real inspection to converge on the same end state a normal successful
    deploy would reach.
    """
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-deploy-crash-resync",
        status="queued", presence="absent",
    )
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="deploy",
        requested_by=None,
        origin="runtime_repair",
        runtime_precondition="absent",
    )
    # First worker incarnation claims the row.
    _claim_row(
        operation, claimed_by="host-a:1:boot1", claimed_host="host-a", claimed_epoch="1:boot1",
    )
    operation.attempts = 1
    admin_session.commit()

    # Simulate run_claimed's capacity-admission reservation commit — this is
    # the durable, pre-slow-work checkpoint that genuinely happens before
    # deploy_if_absent() is ever called, and it is the ONLY DB state a crash
    # immediately after a genuinely successful deploy_if_absent() would ever
    # leave behind (provision_if_absent's own success projection — building
    # consoles, setting status="active" — never got to run).
    instance.status = "provisioning"
    instance.runtime_presence = "unknown"
    admin_session.commit()

    # The worker process crashes here — never runs provision_if_absent's
    # console/status projection, despite the runtime genuinely now running.
    # A fresh worker incarnation's startup reclaim requeues this claim.
    reclaimed = lab_operations.reclaim_previous_epoch(
        admin_session, host="host-a", epoch="2:boot2"
    )
    admin_session.commit()
    assert reclaimed == 1
    admin_session.refresh(operation)
    admin_session.refresh(instance)
    assert operation.state == "queued"
    assert instance.status == "queued"  # provisioning -> queued, same as reconcile_stuck
    assert instance.consoles == {}  # never recorded — the crash gap

    # The new worker incarnation claims the same operation and retries.
    _claim_row(
        operation, claimed_by="host-a:2:boot2", claimed_host="host-a", claimed_epoch="2:boot2",
    )
    operation.attempts += 1
    admin_session.commit()

    engine = _engine(instance.instance_name)
    # Preliminary check correctly observes the runtime IS present — it
    # really was deployed by the crashed attempt.
    engine.status.return_value = "running"
    engine.inspect_running.return_value = LabHandle(
        instance_name=instance.instance_name,
        nodes={"client": f"clab-{instance.instance_name}-client"},
        mgmt={"client": "172.20.20.9"},
        kinds={"client": "linux"},
    )

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="host-a:2:boot2", engine=engine,
    ) == "succeeded"

    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert operation.state == "succeeded"
    # The gap this test guards against: without the resync fix, this would
    # be "queued" with empty consoles despite a genuinely running lab.
    assert instance.status == "active"
    assert instance.consoles != {}
    assert instance.consoles["client"]["mgmt"] == "172.20.20.9"
    assert instance.runtime_presence == "present"
    engine.inspect_running.assert_called_once()
    engine.deploy_if_absent.assert_not_called()  # preliminary short-circuit, never reached


def test_conditional_deploy_precondition_holds_deploys_and_succeeds(admin_session, tenant_a):
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-deploy-ok", status="active", presence="unknown"
    )
    instance.error = "worker lease expired; operation requeued"
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="deploy",
        requested_by=None,
        origin="runtime_repair",
        runtime_precondition="absent",
    )
    _claim(admin_session, operation)
    engine = _engine(instance.instance_name)
    engine.status.return_value = "absent"  # preliminary check: genuinely absent
    engine.deploy_if_absent.return_value = LabHandle(
        instance_name=instance.instance_name, nodes={}, mgmt={}, kinds={},
    )

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "succeeded"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert instance.runtime_presence == "present"
    assert operation.state == "succeeded"
    engine.deploy_if_absent.assert_called_once()
    engine.deploy.assert_not_called()


def test_conditional_deploy_precondition_mismatch_at_preliminary_check_settles_noop(
    admin_session, tenant_a, monkeypatch
):
    """The preliminary check alone (before any capacity admission) finds the
    runtime already present: settle as a successful no-op WITHOUT ever
    calling deploy_if_absent, stop_consoles, or touching status/error."""
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-deploy-prelim-noop",
        status="active", presence="unknown",
    )
    instance.error = None
    instance.consoles = {"client": {"kind": "linux"}}
    admin_session.flush()
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="deploy",
        requested_by=None,
        origin="runtime_repair",
        runtime_precondition="absent",
    )
    _claim(admin_session, operation)
    engine = _engine(instance.instance_name)
    engine.status.return_value = "running"  # preliminary check: genuinely present

    stop_calls = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: stop_calls.append(i.id))

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "succeeded"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert instance.error is None
    assert instance.consoles == {"client": {"kind": "linux"}}
    assert instance.runtime_presence == "present"
    assert stop_calls == []
    engine.deploy_if_absent.assert_not_called()
    engine.deploy.assert_not_called()


def test_conditional_deploy_authoritative_check_catches_a_race_the_preliminary_check_missed(
    admin_session, tenant_a, monkeypatch
):
    """The preliminary check says absent, but a race makes the runtime
    genuinely present by the time deploy_if_absent's own lock-protected check
    runs — proves the SECOND (authoritative) check is the one that actually
    matters, not the first.

    ``consoles`` is pre-populated here, representing the OTHER, genuinely
    concurrent operation's own already-completed deploy (a real race,
    distinct from the crash-then-retry scenario covered by
    ``test_conditional_deploy_crash_then_reclaim_then_retry_resyncs_consoles_and_status``,
    where empty consoles are the signal that this instance's OWN prior
    attempt never got to record them) — so this stays the "preserve as-is"
    path, not the resync path.
    """
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-deploy-race",
        status="active", presence="unknown",
    )
    instance.error = None
    instance.consoles = {"client": {"kind": "linux", "mgmt": "10.0.0.5"}}
    admin_session.flush()
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="deploy",
        requested_by=None,
        origin="runtime_repair",
        runtime_precondition="absent",
    )
    _claim(admin_session, operation)
    engine = _engine(instance.instance_name)
    engine.status.return_value = "absent"  # preliminary check misses the race
    engine.deploy_if_absent.return_value = None  # authoritative check: genuinely present

    stop_calls = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: stop_calls.append(i.id))

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "succeeded"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    engine.deploy_if_absent.assert_called_once()  # the authoritative check DID run
    assert instance.status == "active"  # restored, not left at "resetting"
    assert instance.error is None
    assert instance.runtime_presence == "present"
    assert instance.consoles == {"client": {"kind": "linux", "mgmt": "10.0.0.5"}}  # untouched
    assert stop_calls == []
    engine.deploy.assert_not_called()
    engine.inspect_running.assert_not_called()  # non-empty consoles: no resync needed


def test_conditional_destroy_precondition_holds_destroys_and_stops_consoles_after(
    admin_session, tenant_a, monkeypatch
):
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-destroy-ok", status="reaped", presence="present",
    )
    instance.consoles = {"client": {"kind": "linux"}}
    admin_session.flush()
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="destroy",
        requested_by=None,
        origin="runtime_cleanup",
        runtime_precondition="present",
    )
    _claim(admin_session, operation)
    engine = _engine(instance.instance_name)
    order = []
    engine.destroy_if_present.side_effect = lambda name: order.append("destroy_if_present") or True
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: order.append("stop_consoles"))

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "succeeded"
    admin_session.refresh(instance)
    assert instance.status == "reaped"
    assert instance.runtime_presence == "absent"
    assert order == ["destroy_if_present", "stop_consoles"]
    engine.destroy.assert_not_called()


def test_conditional_destroy_precondition_mismatch_settles_noop(
    admin_session, tenant_a, monkeypatch
):
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-destroy-noop", status="reaped", presence="unknown",
    )
    instance.error = "prior error text"
    instance.consoles = {"client": {"kind": "linux"}}
    admin_session.flush()
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="destroy",
        requested_by=None,
        origin="runtime_cleanup",
        runtime_precondition="present",
    )
    _claim(admin_session, operation)
    engine = _engine(instance.instance_name)
    engine.destroy_if_present.return_value = False  # precondition mismatch: already absent
    stop_calls = []
    monkeypatch.setattr(lab_lifecycle, "stop_consoles", lambda i: stop_calls.append(i.id))

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "succeeded"
    admin_session.refresh(instance)
    assert instance.status == "reaped"
    assert instance.error == "prior error text"
    assert instance.consoles == {"client": {"kind": "linux"}}
    assert instance.runtime_presence == "absent"
    assert stop_calls == []
    engine.destroy.assert_not_called()


def test_conditional_deploy_host_lock_unavailable_restores_initial_state_without_charging_attempt(
    admin_session, tenant_a
):
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-deploy-lock", status="active", presence="unknown",
    )
    instance.error = None
    admin_session.flush()
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="deploy",
        requested_by=None,
        origin="runtime_repair",
        runtime_precondition="absent",
    )
    _claim(admin_session, operation)
    attempts_at_claim = operation.attempts
    engine = _engine(instance.instance_name)
    engine.status.side_effect = host_lock.HostLockUnavailable("host lock held")

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "deferred"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "active"
    assert instance.error is None
    assert instance.runtime_presence == "unknown"
    assert operation.state == "queued"
    assert operation.claimed_by is None
    # Refunded, not charged an extra attempt for lock contention.
    assert operation.attempts == max(attempts_at_claim - 1, 0)


def test_conditional_destroy_host_lock_unavailable_restores_initial_state_without_charging_attempt(
    admin_session, tenant_a
):
    instance, _person = _seed(
        admin_session, tenant_a.id, name="cond-destroy-lock", status="reaped", presence="present",
    )
    admin_session.flush()
    operation = lab_operations.enqueue(
        admin_session,
        instance=instance,
        kind="destroy",
        requested_by=None,
        origin="runtime_cleanup",
        runtime_precondition="present",
    )
    _claim(admin_session, operation)
    attempts_at_claim = operation.attempts
    engine = _engine(instance.instance_name)
    engine.destroy_if_present.side_effect = host_lock.HostLockUnavailable("host lock held")

    assert lab_operations.run_claimed(
        admin_session, operation_id=operation.id, claimed_by="worker", engine=engine,
    ) == "deferred"
    admin_session.refresh(instance)
    admin_session.refresh(operation)
    assert instance.status == "reaped"
    assert instance.runtime_presence == "present"
    assert operation.state == "queued"
    assert operation.attempts == max(attempts_at_claim - 1, 0)
