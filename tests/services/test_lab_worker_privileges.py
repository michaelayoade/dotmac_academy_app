"""Real ``academy_lab_worker`` privilege matrix and worker-consequence integration test.

Skips cleanly when ``TEST_LAB_WORKER_DATABASE_URL`` is unset (see the
``lab_worker_session`` fixture in ``tests/conftest.py``) — this is the one test
in the suite that requires a real, live-verified ``academy_lab_worker`` role rather than
the migration/superuser connection ``admin_session`` provides, because its
whole point is to catch an incomplete or overbroad grant that a superuser
connection would never surface.

Uses a stub (``MagicMock``) containerlab engine only — never a real one.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy import select, text

from app.models.assessment import Score, Submission
from app.models.email_outbox import EmailOutbox
from app.models.lab import LabOperation, LabTemplate
from app.models.learning_event import LearningEvent
from app.models.notification import Notification
from app.services import lab_jobs, lab_operations
from app.services.labengine.interface import ExecResult, LabHandle
from tests.services.test_lab_operations_worker import _seed

# (table, granted privileges, privileges that must NOT be granted)
SELECT_ONLY_TABLES = ("lab_templates", "platform_settings", "activities", "people", "tenants")
SELECT_INSERT_TABLES = (
    "submissions",
    "scores",
    "learning_events",
    "notifications",
    "email_outbox",
)
LAB_INSTANCES_PRIVILEGES = ("SELECT", "UPDATE")


def _stub_engine(instance_name: str) -> MagicMock:
    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name=instance_name,
        nodes={"client": f"clab-{instance_name}-client"},
        mgmt={"client": "10.0.0.5"},
        kinds={"client": "linux"},
    )
    engine.destroy.return_value = None  # absent is already destroyed
    engine.exec.return_value = ExecResult("2 packets transmitted, 2 received", "", 0)
    engine.inventory.return_value = set()  # nothing running per the runtime
    return engine


def _has_privilege(session, table: str, privilege: str) -> bool:
    return bool(
        session.scalar(
            text("SELECT has_table_privilege('academy_lab_worker', :table, :priv)").bindparams(
                table=table, priv=privilege
            )
        )
    )


def test_lab_worker_privilege_matrix_and_worker_consequences(
    admin_session, lab_worker_session, tenant_a
):
    instance, person = _seed(admin_session, tenant_a.id, name="privileges")
    template = admin_session.scalars(
        select(LabTemplate)
        .where(LabTemplate.tenant_id == tenant_a.id)
        .where(LabTemplate.activity_id == instance.activity_id)
    ).one()
    template.checks = [
        {
            "id": "reach",
            "type": "probe",
            "node": "client",
            "probe": {"kind": "ping", "target": "10.0.0.1", "count": 2, "min_success": 1},
            "weight": 1,
        }
    ]
    lab_operations.enqueue(admin_session, instance=instance, kind="deploy", requested_by=person.id)
    admin_session.commit()

    # --- explicit ACL matrix -----------------------------------------------
    expected_direct_acl = {
        "lab_operations": {"INSERT", "SELECT", "UPDATE"},
        "lab_instances": {"SELECT", "UPDATE"},
        **{table: {"SELECT"} for table in SELECT_ONLY_TABLES},
        **{table: {"INSERT", "SELECT"} for table in SELECT_INSERT_TABLES},
    }
    direct_acl = {
        table: set(privileges)
        for table, privileges in lab_worker_session.execute(
            text(
                """SELECT c.relname, array_agg(DISTINCT p.privilege_type ORDER BY p.privilege_type)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(c.relacl, acldefault('r', c.relowner))
                ) p
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND pg_get_userbyid(p.grantee) = 'academy_lab_worker'
                GROUP BY c.relname"""
            )
        ).all()
    }
    assert direct_acl == expected_direct_acl
    assert not lab_worker_session.scalar(
        text("SELECT has_schema_privilege('academy_lab_worker', 'public', 'CREATE')")
    )
    assert lab_worker_session.scalar(
        text("SELECT NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = 'academy_lab_worker'::regrole OR m.roleid = 'academy_lab_worker'::regrole)")
    )

    for table in SELECT_ONLY_TABLES:
        assert _has_privilege(lab_worker_session, table, "SELECT"), f"expected SELECT on {table}"
        assert not _has_privilege(
            lab_worker_session, table, "INSERT"
        ), f"academy_lab_worker should not have INSERT on {table}"

    for table in SELECT_INSERT_TABLES:
        assert _has_privilege(lab_worker_session, table, "SELECT"), f"expected SELECT on {table}"
        assert _has_privilege(lab_worker_session, table, "INSERT"), f"expected INSERT on {table}"
        assert not _has_privilege(
            lab_worker_session, table, "UPDATE"
        ), f"academy_lab_worker should not have UPDATE on {table}"
        assert not _has_privilege(
            lab_worker_session, table, "DELETE"
        ), f"academy_lab_worker should not have DELETE on {table}"

    for privilege in LAB_INSTANCES_PRIVILEGES:
        assert _has_privilege(
            lab_worker_session, "lab_instances", privilege
        ), f"expected {privilege} on lab_instances"

    # --- deploy, then a passing check, through the real worker session --
    engine = _stub_engine(instance.instance_name)
    assert lab_jobs.drain_once(lab_worker_session, engine) == 1
    lab_worker_session.commit()

    lab_operations.enqueue(admin_session, instance=instance, kind="check", requested_by=person.id)
    admin_session.commit()

    assert lab_jobs.drain_once(lab_worker_session, engine) == 1
    lab_worker_session.commit()

    # --- reconcile_runtime: inventory reports nothing running ---------------
    queued, destroyed = lab_jobs.reconcile_runtime(lab_worker_session, engine)
    lab_worker_session.commit()
    assert destroyed == 0
    assert queued >= 1

    # --- verify consequences were actually persisted, not just "no exception"
    admin_session.rollback()
    submission = admin_session.scalars(
        select(Submission).where(Submission.person_id == person.id)
    ).first()
    assert submission is not None

    score = admin_session.scalars(
        select(Score).where(Score.submission_id == submission.id)
    ).first()
    assert score is not None
    assert score.passed is True

    event_kinds = {
        row
        for row in admin_session.scalars(
            select(LearningEvent.kind).where(LearningEvent.person_id == person.id)
        ).all()
    }
    assert {"submission_made", "work_graded", "lab_check_passed"} <= event_kinds

    notification = admin_session.scalars(
        select(Notification).where(Notification.person_id == person.id)
    ).first()
    assert notification is not None

    email = admin_session.scalars(
        select(EmailOutbox).where(EmailOutbox.idempotency_key == f"score-pass:{score.id}")
    ).first()
    assert email is not None

    repair_operation = admin_session.scalars(
        select(LabOperation)
        .where(LabOperation.instance_id == instance.id)
        .where(LabOperation.state == "queued")
        .where(LabOperation.kind == "deploy")
    ).first()
    assert repair_operation is not None
