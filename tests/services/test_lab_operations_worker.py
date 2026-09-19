"""Worker ownership, fencing, recovery, and admission tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.assessment import Activity, Submission
from app.models.course import Course
from app.models.lab import LabInstance, LabOperation, LabTemplate
from app.models.person import Person
from app.services import host_lock, lab_jobs, lab_operations
from app.services.exceptions import ConflictError
from app.services.labengine.containerlab import ContainerlabEngine
from app.services.labengine.interface import LabHandle


def _seed(db, tenant_id, *, name: str = "one", status: str = "queued"):
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

    claimed = lab_operations.claim_next(admin_session, claimed_by="worker")
    assert claimed is not None and claimed.id == operation.id
    admin_session.commit()
    admin_session.refresh(operation)
    assert operation.attempts == 1

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
    operation.claimed_at = datetime.now(UTC) - timedelta(minutes=20)
    operation.heartbeat_at = datetime.now(UTC) - timedelta(minutes=20)
    admin_session.commit()

    assert lab_operations.reconcile_stuck(admin_session, lease_seconds=60) == 1
    admin_session.commit()
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
