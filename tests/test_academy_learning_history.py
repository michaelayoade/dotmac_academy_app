"""Hosted frozen62 actual-source canaries; AUTHORED NOT RUN.

Uses the unchanged genuine legacy replay/entry fixture (max0061 + date-prefix
revisions, 62 source hashes) and actual app_admin Connection/root. No shadow
models, create_all/stamp, replacement packages or authority booleans. Positive
V5 import/readback extends that genuine SAME-root fixture through a003 and real
installed Learning lineages/public bindings; future hosted qualification is owed.
"""

import struct
from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import dotmac_learning as learning
import pytest
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from app.maintenance import learning_history as history
from app.maintenance.account_token_identity import (
    account_token_identity_receipt,
    authorize_historical_account_token_adoption,
    capture_historical_account_tokens,
)
from app.maintenance.identity_history import import_academy_identity_history
from tests import test_academy_identity_history as identity_tests
from tests.fixtures.kernel_identity_entry.rehearsal import verify_legacy_source
from tests.test_kernel_identity_entry import entry_transaction, legacy_engine, public_footprint

assert legacy_engine
_NOW = datetime(2020, 2, 29, 12, 34, 56, 123456, tzinfo=timezone(timedelta(hours=5, minutes=30)))
_IDENTITY = (
    "tenants",
    "tenant_domains",
    "people",
    "user_credentials",
    "auth_sessions",
    "roles",
    "person_roles",
    "audit_events",
)
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


def _lock_complete_source(connection):
    # Test coordinator pre-locks all actual47 + version table BEFORE adapters.
    names = sorted((*history._SOURCE_NAMES, *_IDENTITY, *_RETAINED, "alembic_version"))
    assert len(names) == len(set(names)) == 48
    connection.execute(
        sa.text("LOCK TABLE " + ",".join('public."' + name + '"' for name in names) + " IN ACCESS EXCLUSIVE MODE")
    )


def _seed_all_source_fields(connection):
    """Synthetic values in actual migrated storage, never ORM-created schema."""
    people = connection.execute(sa.text("SELECT tenant_id,id FROM public.people ORDER BY tenant_id,id")).all()
    people = dict(people)
    assert len(people) == 2
    empty_tenant = uuid4()
    connection.execute(
        sa.text("INSERT INTO public.tenants(id,slug,name) VALUES (:id,:slug,'Empty Learning cohort')"),
        {"id": empty_tenant, "slug": empty_tenant.hex},
    )
    expected = {}
    for index, (tenant, person) in enumerate(people.items()):
        ids = {spec.name: uuid4() for spec in history._TABLES}
        pending = list(history._TABLES)
        done = {"tenants", "people"}
        while pending:
            spec = next(spec for spec in pending if all(fk[1] in done for fk in spec.foreign_keys))
            values = {}
            for name, typ, nullable in spec.columns:
                if name == "id":
                    value = ids[spec.name]
                elif name == "tenant_id":
                    value = tenant
                elif nullable and index == 1:
                    value = None
                elif typ == "uuid":
                    references = {
                        "course_id": "courses",
                        "requires_course_id": "courses",
                        "chapter_id": "chapters",
                        "bank_id": "question_banks",
                        "entrance_bank_id": "question_banks",
                        "cohort_id": "cohorts",
                        "track_id": "tracks",
                        "offering_id": "course_offerings",
                        "activity_id": "activities",
                        "submission_id": "submissions",
                        "subject_id": "courses",
                    }
                    value = ids[references[name]] if name in references else person
                elif typ == "timestamp with time zone":
                    value = _NOW + timedelta(microseconds=len(values))
                elif typ == "double precision":
                    value = -0.0 if index == 0 else 0.125
                elif typ == "integer":
                    value = 7 if name in {"number", "chapter_number", "attempt_no"} else -3
                elif typ == "boolean":
                    value = index == 0
                elif typ == "jsonb":
                    values_by_column = {
                        "answers": '{"huge": 1e400, "fraction": 0.12345678901234567890123456789}',
                        "per_item": "12345678901234567890.12345678901234567890",
                        "options": "null",
                        "correct": '["雪", 1, null]',
                        "question_ext_ids": '["x", "x"]',
                        "detail": '"  原 scalar  "',
                        "supporting_facts": '{"unclassified": null}',
                    }
                    value = values_by_column[name]
                elif name == "audience":
                    value = "staff"
                elif name == "employee_ref":
                    value = " Exact employee REF "
                elif name in {"slug", "serial", "ext_id"}:
                    value = ids[spec.name].hex
                else:
                    value = " 原 raw "
                values[name] = value
            relation = sa.table(spec.name, *(sa.column(name) for name in values), schema="public")
            insert_values = {
                name: sa.cast(sa.bindparam(name, type_=sa.Text), JSONB) if typ == "jsonb" else sa.bindparam(name)
                for name, typ, _ in spec.columns
            }
            connection.execute(sa.insert(relation).values(**insert_values), values)
            expected[(spec.name, ids[spec.name])] = values
            pending.remove(spec)
            done.add(spec.name)
    return empty_tenant, expected


@contextmanager
def _populated_source(engine):
    verify_legacy_source()
    with entry_transaction(engine) as connection:
        empty_tenant, expected = _seed_all_source_fields(connection)
        _lock_complete_source(connection)
        capture = history._capture_learning_history(connection)
        try:
            yield connection, capture, empty_tenant, expected
        finally:
            history._release_learning_history(connection, capture)


def _assert_fixed_source_acl_profile(connection):
    """Independent SQL proof of frozen0048/0056/0061 grants, not a live baseline."""
    tables = list(history._SOURCE_NAMES)
    roles = ["app_admin", "app_user", "platform_api", "academy_lab_worker"]
    table_privileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
    worker = {
        ("activities", "SELECT"),
        ("courses", "SELECT"),
        ("course_completions", "SELECT"),
        ("submissions", "SELECT"),
        ("submissions", "INSERT"),
        ("scores", "SELECT"),
        ("scores", "INSERT"),
        ("learning_events", "SELECT"),
        ("learning_events", "INSERT"),
        ("certificates", "SELECT"),
        ("certificates", "INSERT"),
    }
    table_grants = {
        (table, role, privilege)
        for table in tables
        for role in roles
        for privilege in table_privileges
        if (
            role == "app_admin"
            or (role == "academy_lab_worker" and (table, privilege) in worker)
            or (
                role in {"app_user", "platform_api"}
                and privilege
                in (
                    {"SELECT", "INSERT"}
                    if table in {"learning_events", "subtopic_reads"}
                    else {"SELECT", "INSERT", "UPDATE", "DELETE"}
                )
            )
        )
    }
    column_grants = {
        ("course_completions", column, "academy_lab_worker", privilege)
        for privilege, columns in (
            ("INSERT", ("id", "tenant_id", "person_id", "course_id", "status", "pct")),
            ("UPDATE", ("status", "pct", "completed_at", "updated_at")),
        )
        for column in columns
    }
    table_acl = connection.execute(
        sa.text(
            "SELECT c.relname,pg_catalog.pg_get_userbyid(a.grantor),"
            "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
            "a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,"
            "LATERAL pg_catalog.aclexplode(c.relacl) a "
            "WHERE n.nspname='public' AND c.relname=ANY(:tables) ORDER BY 1,2,3,4,5"
        ),
        {"tables": tables},
    ).all()
    assert len(table_acl) == 408
    assert table_acl == sorted((table, "app_admin", role, privilege, False) for table, role, privilege in table_grants)
    column_acl = connection.execute(
        sa.text(
            "SELECT c.relname,t.attname,pg_catalog.pg_get_userbyid(a.grantor),"
            "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,"
            "a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_attribute t ON t.attrelid=c.oid,"
            "LATERAL pg_catalog.aclexplode(t.attacl) a "
            "WHERE n.nspname='public' AND c.relname=ANY(:tables) ORDER BY 1,2,3,4,5,6"
        ),
        {"tables": tables},
    ).all()
    assert len(column_acl) == 10
    assert column_acl == sorted(
        (table, column, "app_admin", role, privilege, False) for table, column, role, privilege in column_grants
    )
    matrix = connection.execute(
        sa.text(
            "SELECT c.relname,r,p,pg_catalog.has_table_privilege(r,c.oid,p) "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,"
            "unnest(CAST(:roles AS text[])) r,unnest(CAST(:privileges AS text[])) p "
            "WHERE n.nspname='public' AND c.relname=ANY(:tables) ORDER BY 1,2,3"
        ),
        {"tables": tables, "roles": roles, "privileges": table_privileges},
    ).all()
    assert len(matrix) == 756
    assert matrix == sorted(
        (table, role, privilege, (table, role, privilege) in table_grants)
        for table in tables
        for role in roles
        for privilege in table_privileges
    )
    column_privileges = ["SELECT", "INSERT", "UPDATE", "REFERENCES"]
    matrix = connection.execute(
        sa.text(
            "SELECT c.relname,a.attname,r,p,pg_catalog.has_column_privilege(r,c.oid,a.attnum,p) "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid,"
            "unnest(CAST(:roles AS text[])) r,unnest(CAST(:privileges AS text[])) p "
            "WHERE n.nspname='public' AND c.relname=ANY(:tables) AND a.attnum>0 ORDER BY 1,2,3,4"
        ),
        {"tables": tables, "roles": roles, "privileges": column_privileges},
    ).all()
    assert len(matrix) == 4176
    assert matrix == sorted(
        (
            spec.name,
            column,
            role,
            privilege,
            (spec.name, role, privilege) in table_grants or (spec.name, column, role, privilege) in column_grants,
        )
        for spec in history._TABLES
        for column, _, _ in spec.columns
        for role in roles
        for privilege in column_privileges
    )
    # SQL column grants permit these writes without table-wide INSERT/UPDATE.
    assert not any(
        row[3]
        for row in connection.execute(
            sa.text(
                "SELECT 'course_completions','academy_lab_worker',p,"
                "pg_catalog.has_table_privilege('academy_lab_worker','public.course_completions',p) "
                "FROM unnest(ARRAY['INSERT','UPDATE']) p"
            )
        )
    )


def test_actual_frozen62_all27_all260_fields_and_nullable_ack_history(legacy_engine):
    with _populated_source(legacy_engine) as (connection, capture, empty_tenant, expected):
        root = connection.get_transaction()
        _assert_fixed_source_acl_profile(connection)
        snapshot = history._export_learning_history(connection, capture)
        acks = history._completion_ack_history(connection, capture)
        assert type(snapshot) is learning.LearningSnapshotV5
        assert len(history._TABLES) == 27
        assert sum(len(fields(spec.row_type)) for spec in history._TABLES) == 260
        assert len(snapshot.tenant_ids) == 3 and empty_tenant in snapshot.tenant_ids
        assert all(getattr(snapshot, spec.name) for spec in history._TABLES)
        assert all(row.tenant_id != empty_tenant for spec in history._TABLES for row in getattr(snapshot, spec.name))
        ack_by_id = {row.id: row for row in acks}
        assert len(acks) == len(snapshot.course_completions)
        assert any(row.erp_synced_at is None for row in acks)
        assert any(row.erp_synced_at is not None for row in acks)
        for spec in history._TABLES:
            for row in getattr(snapshot, spec.name):
                if (spec.name, row.id) not in expected:
                    continue  # Frozen fixture's original course/completion rows also retained.
                original = expected[(spec.name, row.id)]
                for field in fields(row):
                    wanted = original[field.name]
                    observed = getattr(row, field.name)
                    typ = next(typ for name, typ, _ in spec.columns if name == field.name)
                    if wanted is not None and typ == "double precision":
                        assert observed.hex == struct.pack("!d", wanted).hex()
                    elif wanted is not None and typ == "jsonb":
                        native = connection.scalar(sa.text("SELECT CAST(CAST(:raw AS jsonb) AS text)"), {"raw": wanted})
                        assert type(observed) is learning.JsonbText and str(observed) == native
                    else:
                        assert observed == wanted
                if spec.name == "course_completions":
                    assert ack_by_id[row.id].tenant_id == row.tenant_id
                    assert ack_by_id[row.id].erp_synced_at == original["erp_synced_at"]
        assert all(not hasattr(row, "erp_synced_at") for row in snapshot.course_completions)
        assert "storage rows" not in repr(capture) and "fraction" not in repr(capture)
        assert "erp_synced_at" not in repr(acks)
        assert "huge" not in repr(snapshot)
        assert connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize(
    "mutation", ["missing_table", "extra_column", "wrong_type", "fk_action", "extra_incoming", "role", "policy", "acl"]
)
def test_initial_unexpected_source_catalog_reference_or_roles_refuse(legacy_engine, mutation):
    with entry_transaction(legacy_engine) as connection:
        if mutation == "missing_table":
            connection.execute(
                sa.text("ALTER TABLE public.success_queue_entries RENAME TO missing_success_queue_entries")
            )
        elif mutation == "extra_column":
            connection.execute(sa.text("ALTER TABLE public.courses ADD COLUMN undeclared text"))
        elif mutation == "wrong_type":
            connection.execute(sa.text("ALTER TABLE public.courses ALTER COLUMN title TYPE text"))
        elif mutation == "fk_action":
            connection.execute(
                sa.text("ALTER TABLE public.course_completions DROP CONSTRAINT fk_course_completions_tenant_course")
            )
            connection.execute(
                sa.text(
                    "ALTER TABLE public.course_completions ADD CONSTRAINT fk_course_completions_tenant_course "
                    "FOREIGN KEY(tenant_id,course_id) REFERENCES public.courses(tenant_id,id) ON DELETE RESTRICT"
                )
            )
        elif mutation == "extra_incoming":
            connection.execute(
                sa.text(
                    "ALTER TABLE public.applicants ADD CONSTRAINT unexpected_course_reference "
                    "FOREIGN KEY(tenant_id,cohort_id) REFERENCES public.courses(tenant_id,id) NOT VALID"
                )
            )
        elif mutation == "role":
            # No cluster role mutation: SET ROLE is connection-scoped actual authority.
            connection.execute(sa.text("SET LOCAL ROLE app_user"))
        elif mutation == "policy":
            connection.execute(sa.text("ALTER POLICY courses_tenant_isolation ON public.courses USING (true)"))
        elif mutation == "acl":
            connection.execute(sa.text("GRANT UPDATE ON public.learning_events TO app_user"))
        with pytest.raises(history.LearningHistoryRefused):
            history._capture_learning_history(connection)


@pytest.mark.parametrize("role", ["app_user", "platform_api"])
@pytest.mark.parametrize("privilege", ["UPDATE", "DELETE"])
def test_extra_subtopic_read_mutation_grant_refuses_capture(legacy_engine, role, privilege):
    with entry_transaction(legacy_engine) as connection:
        _lock_complete_source(connection)
        # Establish a successful capture of this actual source before changing
        # only its ACL, so an unrelated source refusal cannot satisfy the canary.
        capture = history._capture_learning_history(connection)
        history._release_learning_history(connection, capture)
        connection.execute(sa.text(f"GRANT {privilege} ON public.subtopic_reads TO {role}"))
        assert (
            connection.scalar(
                sa.text("SELECT pg_catalog.has_table_privilege(:role,'public.subtopic_reads',:privilege)"),
                {"role": role, "privilege": privilege},
            )
            is True
        )
        with pytest.raises(history.LearningHistoryRefused):
            history._capture_learning_history(connection)


@pytest.mark.parametrize(
    "table,privilege", [("activities", "INSERT"), ("submissions", "DELETE"), ("question_banks", "SELECT")]
)
def test_extra_worker_learning_grant_refuses_capture(legacy_engine, table, privilege):
    with entry_transaction(legacy_engine) as connection:
        _lock_complete_source(connection)
        capture = history._capture_learning_history(connection)
        history._release_learning_history(connection, capture)
        connection.execute(sa.text(f"GRANT {privilege} ON public.{table} TO academy_lab_worker"))
        assert (
            connection.scalar(
                sa.text("SELECT pg_catalog.has_table_privilege('academy_lab_worker',:table,:privilege)"),
                {"table": f"public.{table}", "privilege": privilege},
            )
            is True
        )
        with pytest.raises(history.LearningHistoryRefused):
            history._capture_learning_history(connection)


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER ROLE academy_lab_worker SUPERUSER",
        "ALTER ROLE academy_lab_worker NOLOGIN",
        "ALTER ROLE academy_lab_worker NOBYPASSRLS",
        "ALTER ROLE academy_lab_worker INHERIT",
        "ALTER ROLE academy_lab_worker CREATEROLE",
        "ALTER ROLE academy_lab_worker CREATEDB",
        "ALTER ROLE academy_lab_worker REPLICATION",
        "ALTER ROLE academy_lab_worker SET row_security TO off",
        "GRANT app_admin TO academy_lab_worker",
        "GRANT academy_lab_worker TO outbox_dispatcher",
        "ALTER ROLE app_admin SUPERUSER",
        "ALTER ROLE app_admin CREATEROLE",
        "ALTER ROLE app_admin CREATEDB",
        "ALTER ROLE app_admin REPLICATION",
        "ALTER ROLE app_admin NOLOGIN",
        "ALTER ROLE app_admin NOBYPASSRLS",
        "ALTER ROLE app_admin NOINHERIT",
        "ALTER ROLE app_admin SET row_security TO off",
        "ALTER ROLE app_user NOINHERIT",
        "ALTER ROLE app_user NOLOGIN",
        "ALTER ROLE app_user SET row_security TO off",
        "ALTER ROLE platform_api NOINHERIT",
        "ALTER ROLE platform_api NOLOGIN",
        "ALTER ROLE platform_api SET row_security TO off",
        "GRANT app_admin TO outbox_dispatcher",
    ],
)
def test_worker_role_authority_drift_refuses_capture(legacy_engine, statement):
    with entry_transaction(legacy_engine) as connection:
        _lock_complete_source(connection)
        capture = history._capture_learning_history(connection)
        history._release_learning_history(connection, capture)
        # Hosted fixture's provisioning identity owns these transaction-local
        # negative mutations; return to app_admin for the actual boundary.
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        connection.execute(sa.text(statement))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(history.LearningHistoryRefused):
            history._capture_learning_history(connection)


def test_late_worker_membership_drift_refuses_export(legacy_engine):
    with _populated_source(legacy_engine) as (connection, capture, _, __):
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        connection.execute(sa.text("GRANT academy_lab_worker TO outbox_dispatcher"))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, capture)


@pytest.mark.parametrize(
    "statement",
    [
        "REVOKE SELECT ON public.courses FROM academy_lab_worker",
        "REVOKE INSERT(id) ON public.course_completions FROM academy_lab_worker",
        "REVOKE UPDATE(status) ON public.course_completions FROM academy_lab_worker",
        "GRANT INSERT ON public.course_completions TO academy_lab_worker",
        "GRANT UPDATE(person_id) ON public.course_completions TO academy_lab_worker",
        "GRANT INSERT(erp_synced_at) ON public.course_completions TO academy_lab_worker",
        "GRANT SELECT(id) ON public.courses TO academy_lab_worker",
        "GRANT SELECT(status) ON public.course_completions TO app_user",
        "GRANT SELECT ON public.activities TO academy_lab_worker WITH GRANT OPTION",
        "GRANT UPDATE(status) ON public.course_completions TO academy_lab_worker WITH GRANT OPTION",
        "GRANT SELECT(status) ON public.course_completions TO PUBLIC",
        "GRANT SELECT(status) ON public.course_completions TO outbox_dispatcher",
        "GRANT SELECT ON public.question_banks TO PUBLIC",
        "GRANT SELECT ON public.question_banks TO outbox_dispatcher",
        "UPDATE pg_catalog.pg_attribute SET attacl='{}'::aclitem[] "
        "WHERE attrelid='public.courses'::regclass AND attname='id'",
        "UPDATE pg_catalog.pg_attribute SET attacl='{}'::aclitem[] "
        "WHERE attrelid='public.courses'::regclass AND attname='ctid'",
    ],
)
def test_exact_learning_table_and_column_acl_drift_refuses_capture(legacy_engine, statement):
    with entry_transaction(legacy_engine) as connection:
        _lock_complete_source(connection)
        capture = history._capture_learning_history(connection)
        history._release_learning_history(connection, capture)
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        connection.execute(sa.text(statement))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        with pytest.raises(history.LearningHistoryRefused):
            history._capture_learning_history(connection)


def _raw_learning_column_acls(connection):
    return connection.execute(
        sa.text(
            "SELECT c.relname,a.attnum,a.attacl::text FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid "
            "WHERE n.nspname='public' AND c.relname=ANY(:tables) ORDER BY 1,2"
        ),
        {"tables": list(history._SOURCE_NAMES)},
    ).all()


@pytest.mark.parametrize("relocated", [False, True], ids=["source", "genuine-identity-relocation"])
@pytest.mark.parametrize("mutation", ["add", "remove", "grant_option"])
def test_late_column_acl_drift_refuses_and_root_rollback_restores_source(
    legacy_engine,
    tmp_path,
    monkeypatch,
    relocated,
    mutation,
):
    with legacy_engine.connect() as connection:
        before = public_footprint(connection)
        before_columns = _raw_learning_column_acls(connection)
    source = (
        _identity_imported_source(legacy_engine, tmp_path, monkeypatch)
        if relocated
        else _populated_source(legacy_engine)
    )
    with source as (connection, capture, _, __):
        assert history._export_learning_history(connection, capture).version == 5
        root = connection.get_transaction()
        statement = {
            "add": "GRANT UPDATE(person_id) ON public.course_completions TO academy_lab_worker",
            "remove": "REVOKE INSERT(id) ON public.course_completions FROM academy_lab_worker",
            "grant_option": (
                "GRANT UPDATE(status) ON public.course_completions TO academy_lab_worker WITH GRANT OPTION"
            ),
        }[mutation]
        connection.execute(sa.text(statement))
        assert _raw_learning_column_acls(connection) != before_columns
        assert connection.get_transaction() is root and root.is_active
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, capture)
    with legacy_engine.connect() as connection:
        assert public_footprint(connection) == before
        assert _raw_learning_column_acls(connection) == before_columns
        assert connection.scalar(sa.text("SELECT to_regclass('public.parties')")) is None
        assert connection.scalar(sa.text("SELECT to_regnamespace('mod_learning')")) is None
        assert connection.scalar(sa.text("SELECT to_regnamespace('academy_identity_compat')")) is None


@pytest.mark.parametrize("mutation", ["row", "delete", "ack", "tenant", "catalog", "oid"])
def test_late_same_root_source_drift_refuses_instead_of_partial_export(legacy_engine, mutation):
    with _populated_source(legacy_engine) as (connection, capture, _, expected):
        course = next(values for (table, _), values in expected.items() if table == "courses")
        if mutation == "row":
            connection.execute(sa.text("UPDATE public.courses SET title='changed' WHERE id=:id"), {"id": course["id"]})
        elif mutation == "delete":
            # An independent ledger row has no children; legitimate delete remains visible.
            connection.execute(sa.text("DELETE FROM public.learning_events"))
        elif mutation == "ack":
            connection.execute(sa.text("UPDATE public.course_completions SET erp_synced_at=now()"))
        elif mutation == "tenant":
            identity = uuid4()
            connection.execute(
                sa.text("INSERT INTO public.tenants(id,slug,name) VALUES (:id,:slug,'late')"),
                {"id": identity, "slug": identity.hex},
            )
        elif mutation == "catalog":
            connection.execute(sa.text("ALTER TABLE public.courses ALTER COLUMN title SET DEFAULT 'late'"))
        else:
            connection.execute(
                sa.text("ALTER TABLE public.success_queue_entries RENAME TO replaced_success_queue_entries")
            )
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, capture)


def test_same_connection_root_and_exact_privately_issued_handle_required(legacy_engine):
    with _populated_source(legacy_engine) as (connection, capture, _, __):
        with pytest.raises(history.LearningHistoryRefused):
            history._Capture()
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, object.__new__(history._Capture))
        with legacy_engine.connect() as other:
            with other.begin():
                other.execute(sa.text("SET LOCAL ROLE app_admin"))
                with pytest.raises(history.LearningHistoryRefused):
                    history._export_learning_history(other, capture)
        with connection.begin_nested():
            with pytest.raises(history.LearningHistoryRefused):
                history._export_learning_history(connection, capture)
        assert history._export_learning_history(connection, capture).version == 5


def test_partial_tenant_rls_app_user_refuses_before_reading_a_subset(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
        tenant = connection.scalar(sa.text("SELECT id FROM public.tenants ORDER BY id LIMIT 1"))
        connection.execute(sa.text("SELECT set_config('app.current_tenant',:id,true)"), {"id": str(tenant)})
        connection.execute(sa.text("SET LOCAL ROLE app_user"))
        assert set(connection.scalars(sa.text("SELECT DISTINCT tenant_id FROM public.courses"))) == {tenant}
        with pytest.raises(history.LearningHistoryRefused):
            history._capture_learning_history(connection)


def test_public_v5_observation_or_snapshot_is_never_capture_authority(legacy_engine):
    with _populated_source(legacy_engine) as (connection, capture, _, __):
        snapshot = history._export_learning_history(connection, capture)
        forged = learning.VerificationObservationV5(version=5, tenant_ids=snapshot.tenant_ids, row_counts=())
        for public_value in (snapshot, forged):
            with pytest.raises(history.LearningHistoryRefused):
                history._export_learning_history(connection, public_value)
        # No canonical namespace exists yet: equality must refuse, never infer
        # fresh success from a public observation or empty canonical storage.
        with pytest.raises(history.LearningHistoryRefused):
            history._verify_canonical_learning_history(connection, capture)


@contextmanager
def _identity_imported_source(engine, tmp_path, monkeypatch):
    captured = []
    real_setup = identity_tests._synthetic_source_setup
    real_relocate = identity_tests.relocate

    def setup(connection):
        real_setup(connection)
        _seed_all_source_fields(connection)
        _lock_complete_source(connection)

    def relocate(connection, plan):
        handle = history._capture_learning_history(connection)
        token_entry = capture_historical_account_tokens(connection)
        captured.append((connection, handle, token_entry))
        return real_relocate(connection, plan)

    with monkeypatch.context() as patch:
        patch.setattr(identity_tests, "_synthetic_source_setup", setup)
        patch.setattr(identity_tests, "relocate", relocate)
        with identity_tests._prepared(engine, tmp_path, patch) as (connection, expected, operation):
            handle = captured[0][1]
            try:
                receipt = import_academy_identity_history(connection, expected, operation)
                assert receipt is not None
                history._observe_identity_relocation(connection, handle)
                yield connection, handle, captured[0][2], receipt
            finally:
                history._release_learning_history(connection, handle)


def test_actual_private_identity_import_allows_only_same_oid_expected_relocation(legacy_engine, tmp_path, monkeypatch):
    with _identity_imported_source(legacy_engine, tmp_path, monkeypatch) as (connection, capture, _, __):
        snapshot = history._export_learning_history(connection, capture)
        assert len(snapshot.tenant_ids) == 3
        assert len(history._completion_ack_history(connection, capture)) == len(snapshot.course_completions)
        connection.execute(sa.text("ALTER TABLE academy_identity_compat.people RENAME TO undeclared_people"))
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, capture)


def test_same_oid_namespace_move_without_actual_import_hook_is_not_authority(legacy_engine, monkeypatch):
    with _populated_source(legacy_engine) as (connection, capture, _, __):
        connection.execute(sa.text("CREATE SCHEMA academy_identity_compat AUTHORIZATION app_admin"))
        for name in ("tenants", "people", "alembic_version"):
            connection.execute(sa.text(f"ALTER TABLE public.{name} SET SCHEMA academy_identity_compat"))
        with pytest.raises(history.LearningHistoryRefused):
            history._observe_identity_relocation(connection, capture)
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, capture)


def test_late_source_failure_rolls_back_real_identity_import_and_canonical_ddl(legacy_engine, tmp_path, monkeypatch):
    with legacy_engine.connect() as connection:
        before = public_footprint(connection)
    with pytest.raises(history.LearningHistoryRefused):
        with _identity_imported_source(legacy_engine, tmp_path, monkeypatch) as (connection, capture, _, __):
            assert connection.scalar(sa.text("SELECT count(*) FROM public.parties")) > 0
            connection.execute(sa.text("UPDATE public.course_completions SET erp_synced_at=now()"))
            history._export_learning_history(connection, capture)
    with legacy_engine.connect() as connection:
        assert public_footprint(connection) == before
        assert connection.scalar(sa.text("SELECT to_regclass('public.parties')")) is None


def test_reused_connection_new_root_does_not_reuse_old_capture(legacy_engine):
    with legacy_engine.connect() as connection:
        root = connection.begin()
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        capture = history._capture_learning_history(connection)
        root.rollback()
        try:
            with connection.begin():
                connection.execute(sa.text("SET LOCAL ROLE app_admin"))
                with pytest.raises(history.LearningHistoryRefused):
                    history._export_learning_history(connection, capture)
        finally:
            history._release_learning_history(connection, capture)


def test_returned_public_snapshot_tampering_cannot_change_private_source_export(legacy_engine):
    with _populated_source(legacy_engine) as (connection, capture, _, __):
        snapshot = history._export_learning_history(connection, capture)
        object.__setattr__(snapshot, "courses", ())
        with pytest.raises(history.LearningHistoryRefused):
            history._export_learning_history(connection, capture)


@contextmanager
def _canonical_learning_import(engine, tmp_path, monkeypatch):
    from dotmac_kernel.prerequisites import (
        MODULE_DATABASE_ROLES_V1,
        PARTY_PERSON_CATALOG_V1,
        TENANT_AUDIT_LOG_V1,
        TENANT_SCOPE_CATALOG_V1,
        PrerequisiteBinding,
        install_prerequisite_bindings,
        installed_bindings,
    )

    from alembic import command
    from tests.fixtures.kernel_identity_entry.rehearsal import composed_config_for

    # Exact actual f674/a1 assembly providers; no latest-head invention. Public
    # binding installation precedes any Learning ScriptDirectory/map loading.
    prior_bindings = installed_bindings()
    actual_bindings = (
        PrerequisiteBinding(TENANT_SCOPE_CATALOG_V1.name, "0001_initial_tenant_schema", "kernel"),
        PrerequisiteBinding(MODULE_DATABASE_ROLES_V1.name, "0001_initial_tenant_schema", "kernel"),
        PrerequisiteBinding(PARTY_PERSON_CATALOG_V1.name, "0003_party_identity", "kernel"),
        PrerequisiteBinding(TENANT_AUDIT_LOG_V1.name, "0029_audit_history_shape", "kernel"),
    )
    try:
        with _identity_imported_source(engine, tmp_path, monkeypatch) as (connection, capture, entry, receipt):
            install_prerequisite_bindings(actual_bindings)
            applied = []
            cfg = composed_config_for(connection, tmp_path / "full-learning", applied)
            authorize_historical_account_token_adoption(connection, entry, receipt)
            command.upgrade(cfg, "a003_account_token_identity")
            # Required immediate capture consumes/deletes the OTHER owner's
            # state. Our earlier genuine observation remains bound to this root.
            token_receipt = account_token_identity_receipt(connection, entry)
            assert token_receipt.identity_import_receipt is receipt
            assert history._identity_issued(connection) is None
            assert history._export_learning_history(connection, capture).version == 5
            command.upgrade(cfg, "learning@head")
            assert any(item.revision == "lr_0006_delivery_support" for item in applied)
            snapshot = history._export_learning_history(connection, capture)
            observation = learning.import_snapshot_v5(connection, snapshot)
            assert observation.version == 5
            yield connection, capture, snapshot
    finally:
        install_prerequisite_bindings(prior_bindings)


def test_real_a003_receipt_then_full_installed_learning_import_and_independent_readback(
    legacy_engine, tmp_path, monkeypatch
):
    with _canonical_learning_import(legacy_engine, tmp_path, monkeypatch) as (connection, capture, snapshot):
        root = connection.get_transaction()
        observation = history._verify_canonical_learning_history(connection, capture)
        assert observation.version == 5 and observation.matched is True
        assert len(observation.row_counts) == 27
        assert {row.table for row in observation.row_counts} == set(history._SOURCE_NAMES)
        assert learning.export_snapshot_v5(connection, snapshot.tenant_ids) == snapshot
        assert len(history._completion_ack_history(connection, capture)) == len(snapshot.course_completions)
        assert connection.get_transaction() is root and root.is_active


@pytest.mark.parametrize("stage", ["canonical_row", "source_ack"])
def test_late_real_learning_readback_failure_rolls_back_entire_adoption_root(
    legacy_engine, tmp_path, monkeypatch, stage
):
    with legacy_engine.connect() as connection:
        before = public_footprint(connection)
    with pytest.raises(history.LearningHistoryRefused):
        with _canonical_learning_import(legacy_engine, tmp_path, monkeypatch) as (connection, capture, snapshot):
            if stage == "canonical_row":
                connection.execute(
                    sa.text("DELETE FROM mod_learning.learning_events WHERE id=:id"),
                    {"id": snapshot.learning_events[0].id},
                )
            else:
                connection.execute(sa.text("UPDATE public.course_completions SET erp_synced_at=now()"))
            history._verify_canonical_learning_history(connection, capture)
    with legacy_engine.connect() as connection:
        assert public_footprint(connection) == before
        assert connection.scalar(sa.text("SELECT to_regnamespace('mod_learning')")) is None
        assert connection.scalar(sa.text("SELECT to_regclass('public.parties')")) is None


def test_driver_transaction_restart_cannot_hide_behind_same_sqlalchemy_root(legacy_engine):
    # Read-only capture; no fixture rows or DDL are committed by this canary.
    with legacy_engine.connect() as connection:
        root = connection.begin()
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        capture = history._capture_learning_history(connection)
        try:
            connection.connection.driver_connection.commit()
            connection.execute(sa.text("SET LOCAL ROLE app_admin"))
            assert connection.get_transaction() is root and root.is_active
            with pytest.raises(history.LearningHistoryRefused):
                history._export_learning_history(connection, capture)
        finally:
            history._release_learning_history(connection, capture)
            root.rollback()
