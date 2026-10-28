"""0064 adds scoped facilitator nominations and backfills legacy assignments."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine, text

from alembic import command
from alembic.script import ScriptDirectory
from tests.test_migration_roundtrip import _make_config, _migration_env, _migration_url

REVISION = "0064_facilitator_nominations"
DOWN_REVISION = "0063_lab_console_activity"


def _table_exists(conn, table: str) -> bool:
    return bool(conn.scalar(text("SELECT to_regclass(:table) IS NOT NULL"), {"table": table}))


def _activation_capability_exists(conn) -> bool:
    return bool(
        conn.scalar(
            text(
                "SELECT to_regprocedure("
                "'public.activate_eligible_facilitator_nominations(uuid,uuid,uuid,uuid,integer,uuid)'"
                ") IS NOT NULL"
            )
        )
    )


def test_0064_roundtrip_backfills_active_legacy_facilitator_without_mutating_enrollment():
    url = _migration_url()
    cfg = _make_config()
    # Predecessor-aware (0065 is head since the D1 renumber): this revision
    # must exist and be reachable; the cycle below still exercises exactly
    # the 0063 <-> 0064 boundary, mirroring the 0062/0063 roundtrips.
    assert ScriptDirectory.from_config(cfg).get_revision(REVISION) is not None
    engine = create_engine(url, future=True)
    tenant_id = uuid4()
    person_id = uuid4()
    cohort_id = uuid4()
    enrollment_id = uuid4()
    role_id = uuid4()
    person_role_id = uuid4()
    orphan_person_id = uuid4()
    orphan_enrollment_id = uuid4()
    try:
        with _migration_env(url):
            command.downgrade(cfg, DOWN_REVISION)
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO tenants (id, slug, name) VALUES (:id, :slug, :name)"),
                {"id": tenant_id, "slug": f"facilitator-0064-{tenant_id.hex[:8]}", "name": "Facilitator 0064"},
            )
            conn.execute(
                text(
                    "INSERT INTO people (id, tenant_id, email, first_name, last_name) "
                    "VALUES (:id, :tenant_id, :email, 'Legacy', 'Instructor')"
                ),
                {"id": person_id, "tenant_id": tenant_id, "email": f"legacy-{person_id.hex[:8]}@example.test"},
            )
            conn.execute(
                text(
                    "INSERT INTO people (id, tenant_id, email, first_name, last_name) "
                    "VALUES (:id, :tenant_id, :email, 'Orphan', 'Enrollment')"
                ),
                {
                    "id": orphan_person_id,
                    "tenant_id": tenant_id,
                    "email": f"orphan-{orphan_person_id.hex[:8]}@example.test",
                },
            )
            conn.execute(
                text(
                    "INSERT INTO cohorts (id, tenant_id, name, discipline, status) "
                    "VALUES (:id, :tenant_id, 'Legacy Cohort', 'networking', 'active')"
                ),
                {"id": cohort_id, "tenant_id": tenant_id},
            )
            conn.execute(
                text(
                    "INSERT INTO roles (id, tenant_id, slug, name) "
                    "VALUES (:id, :tenant_id, 'instructor', 'Instructor')"
                ),
                {"id": role_id, "tenant_id": tenant_id},
            )
            conn.execute(
                text(
                    "INSERT INTO person_roles (id, tenant_id, person_id, role_id) "
                    "VALUES (:id, :tenant_id, :person_id, :role_id)"
                ),
                {
                    "id": person_role_id,
                    "tenant_id": tenant_id,
                    "person_id": person_id,
                    "role_id": role_id,
                },
            )
            conn.execute(
                text(
                    "INSERT INTO enrollments "
                    "(id, tenant_id, cohort_id, person_id, role_in_cohort, status) "
                    "VALUES (:id, :tenant_id, :cohort_id, :person_id, 'instructor', 'active')"
                ),
                {
                    "id": enrollment_id,
                    "tenant_id": tenant_id,
                    "cohort_id": cohort_id,
                    "person_id": person_id,
                },
            )
            conn.execute(
                text(
                    "INSERT INTO enrollments "
                    "(id, tenant_id, cohort_id, person_id, role_in_cohort, status) "
                    "VALUES (:id, :tenant_id, :cohort_id, :person_id, 'instructor', 'active')"
                ),
                {
                    "id": orphan_enrollment_id,
                    "tenant_id": tenant_id,
                    "cohort_id": cohort_id,
                    "person_id": orphan_person_id,
                },
            )

        with _migration_env(url):
            command.upgrade(cfg, REVISION)
        with engine.connect() as conn:
            assert _table_exists(conn, "facilitator_nominations")
            assert _table_exists(conn, "facilitator_requirements")
            assert _activation_capability_exists(conn)
            row = conn.execute(
                text(
                    "SELECT scope_type, status, activation_reason FROM facilitator_nominations "
                    "WHERE tenant_id = :tenant_id AND person_id = :person_id"
                ),
                {"tenant_id": tenant_id, "person_id": person_id},
            ).one()
            assert tuple(row) == ("cohort", "active", "legacy_grandfathered")
            assert (
                conn.scalar(
                    text(
                        "SELECT count(*) FROM facilitator_nominations "
                        "WHERE tenant_id = :tenant_id AND person_id = :person_id"
                    ),
                    {"tenant_id": tenant_id, "person_id": orphan_person_id},
                )
                == 0
            )
            legacy = conn.execute(
                text("SELECT role_in_cohort, status FROM enrollments " "WHERE tenant_id = :tenant_id AND id = :id"),
                {"tenant_id": tenant_id, "id": enrollment_id},
            ).one()
            assert tuple(legacy) == ("instructor", "active")
            rls = conn.execute(
                text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relname IN ('facilitator_nominations', 'facilitator_requirements') "
                    "ORDER BY relname"
                )
            ).all()
            assert rls == [
                ("facilitator_nominations", True, True),
                ("facilitator_requirements", True, True),
            ]
            constraints = dict(
                conn.execute(
                    text(
                        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conname IN ("
                        "'fk_facilitator_nominations_person', "
                        "'fk_facilitator_nominations_offering', "
                        "'fk_facilitator_requirements_nomination', "
                        "'fk_facilitator_requirements_course')"
                    )
                ).all()
            )
            assert "FOREIGN KEY (tenant_id, person_id)" in constraints["fk_facilitator_nominations_person"]
            assert "FOREIGN KEY (tenant_id, offering_id)" in constraints["fk_facilitator_nominations_offering"]
            assert "FOREIGN KEY (tenant_id, nomination_id)" in constraints["fk_facilitator_requirements_nomination"]
            assert "FOREIGN KEY (tenant_id, course_id)" in constraints["fk_facilitator_requirements_course"]
            capability = conn.execute(
                text(
                    """SELECT p.prosecdef, p.proconfig, p.provolatile, p.proparallel,
                              p.proisstrict,
                              pg_get_userbyid(p.proowner) = current_user AS owned_by_migrator,
                              NOT EXISTS (
                                  SELECT 1 FROM aclexplode(p.proacl) acl WHERE acl.grantee = 0
                              ) AS public_revoked,
                              has_function_privilege(
                                  'academy_lab_worker', p.oid, 'EXECUTE'
                              ) AS worker_execute,
                              (
                                  SELECT array_agg(pg_get_userbyid(acl.grantee) ORDER BY pg_get_userbyid(acl.grantee))
                                    FROM aclexplode(p.proacl) acl
                                   WHERE acl.privilege_type = 'EXECUTE'
                                     AND acl.grantee <> p.proowner
                              ) AS execute_grantees
                         FROM pg_proc p
                        WHERE p.oid = to_regprocedure(
                            'public.activate_eligible_facilitator_nominations(uuid,uuid,uuid,uuid,integer,uuid)'
                        )"""
                )
            ).one()
            assert tuple(capability) == (
                True,
                ["search_path=pg_catalog"],
                "v",
                "u",
                False,
                True,
                True,
                True,
                ["academy_lab_worker", "app_user", "platform_api"],
            )
            for table in ("facilitator_nominations", "facilitator_requirements", "audit_events"):
                assert not conn.scalar(
                    text("SELECT has_table_privilege(" "'academy_lab_worker', :table, 'SELECT,INSERT,UPDATE,DELETE')"),
                    {"table": table},
                )

        with _migration_env(url):
            command.downgrade(cfg, DOWN_REVISION)
        with engine.connect() as conn:
            assert not _table_exists(conn, "facilitator_nominations")
            assert not _table_exists(conn, "facilitator_requirements")
            assert not _activation_capability_exists(conn)
    finally:
        with _migration_env(url):
            command.upgrade(cfg, "head")
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        engine.dispose()
