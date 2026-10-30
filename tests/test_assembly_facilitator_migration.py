"""a010 canonical port of legacy 0064: hosted catalog and real-login proofs.

Catalog and staged-grandfather tests use rolled-back fresh roots; the staged
proof stops before an empty fresh receipt. Real-login/concurrency proofs use a
separately provisioned, qualified and committed disposable canonical database.
"""

from __future__ import annotations

import ast
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from dotmac_kernel.models import Party, PartyRoleGrant, PartyType, Role, Tenant
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from alembic import command
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.migration_graph import ordinary_migration_config
from app.models.cohort import Enrollment
from app.models.completion import CourseCompletion
from app.models.facilitator import FacilitatorNomination, FacilitatorRequirement
from tests.services.test_facilitator_nominations import _cohort, _course, _offering, _person

REVISION = "a010_facilitator_nominations"
FUNCTION = "public.activate_eligible_facilitator_nominations(uuid,uuid,uuid,uuid,integer,uuid)"
RUNTIME_ROLES = ("app_user", "platform_api", "academy_lab_worker")


def _migration():
    return ScriptDirectory.from_config(ordinary_migration_config()).get_revision(REVISION).module


def test_a010_canonical_source_contract_and_downgrade_refusal():
    module = _migration()
    source = Path(module.__file__).read_text()
    ast.parse(source)
    assert module.down_revision == "a009_applicant_bank_version_pin"
    for old in ("public.people", "person_roles", "public.course_completions", "academy_identity_compat"):
        assert old not in source
    for expected in (
        "public.party_persons.party_id", "fk_facilitator_nominations_person_subtype",
        "fk_facilitator_nominations_nominator_subtype", "mod_learning.cohorts.tenant_id",
        "mod_learning.course_offerings.tenant_id", "mod_learning.courses.tenant_id",
        "JOIN public.party_role_grants", "JOIN public.roles", "r.slug = 'instructor'",
        "actor_type, actor_id, actor_party_id, source_application", "'facilitator_activation'",
        "'dotmac_academy_app'", "SET search_path = pg_catalog", "FOR UPDATE OF n SKIP LOCKED",
    ):
        assert expected in source
    with pytest.raises(RuntimeError, match="reviewed new-facts disposition"):
        module.downgrade()


@pytest.fixture
def fresh_target():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    assert os.environ.get("CI") == "true", "a010 database proofs are hosted CI only"
    raw = os.environ.get("ACADEMY_FRESH_ENTRY_DATABASE_URL")
    assert raw, "CI must provision the dedicated fresh-entry database"
    url = make_url(raw)
    assert url.drivername == "postgresql+psycopg" and url.username == "app_admin" and url.database
    for name, value in os.environ.items():
        if name.endswith("DATABASE_URL") and name != "ACADEMY_FRESH_ENTRY_DATABASE_URL" and value:
            assert url.database != make_url(value).database
    engine = create_engine(url, hide_parameters=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            root = connection.begin()
            try:
                yield connection
                assert connection.get_transaction() is root and root.is_active
            finally:
                root.rollback()
    finally:
        engine.dispose()


@pytest.fixture
def assembly_db(fresh_target):
    from app.maintenance.fresh_product import rehearse_fresh_composed_entry

    rehearse_fresh_composed_entry(fresh_target, decision_ref="C4 a010 rolled-back security rehearsal")
    return fresh_target


@pytest.fixture(scope="module")
def runtime_engine():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    from app.maintenance.fresh_product import run_fresh_composed_entry

    assert os.environ.get("CI") == os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux"
    assert os.environ.get("GITHUB_REPOSITORY") == "michaelayoade/dotmac_academy_app"
    raw = os.environ.get("ACADEMY_FACILITATOR_RUNTIME_DATABASE_URL")
    assert raw, "CI must provision ACADEMY_FACILITATOR_RUNTIME_DATABASE_URL"
    url = make_url(raw)
    assert url.drivername == "postgresql+psycopg" and url.username == "app_admin"
    assert url.database == "academy_facilitator_runtime"
    assert url.host in ("localhost", "127.0.0.1") and url.port == 5437 and not url.query
    for name, value in os.environ.items():
        if name.endswith("DATABASE_URL") and name != "ACADEMY_FACILITATOR_RUNTIME_DATABASE_URL" and value:
            assert url.database != make_url(value).database, "runtime proof database must be isolated"
    engine = create_engine(url, hide_parameters=True, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            root = connection.get_transaction()
            assert connection.execute(text("""
                SELECT session_user,current_user,current_database(),pg_catalog.pg_get_userbyid(d.datdba)
                FROM pg_catalog.pg_database d WHERE d.datname=current_database()
            """)).one() == ("app_admin", "app_admin", "academy_facilitator_runtime", "app_admin")
            assert connection.scalar(text("""
                SELECT count(*) FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
            """)) == 0
            # The strict, independently pinned path owns empty-target checks.
            # This isolated test database deliberately commits its qualified receipt.
            run_fresh_composed_entry(connection, decision_ref="C4 dedicated runtime-principal proof database")
            assert connection.get_transaction() is root and root.is_active
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def runtime_db(runtime_engine):
    with runtime_engine.connect() as connection:
        connection.info["a010_tenants"] = []
        try:
            yield connection
        finally:
            connection.rollback()
            for tenant_id in connection.info.pop("a010_tenants"):
                connection.execute(text("DELETE FROM public.tenants WHERE id=:id"), {"id": tenant_id})
            connection.commit()


@contextmanager
def _principal(connection, role, tenant_id):
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    assert role in RUNTIME_ROLES
    # CI provisions these three disposable logins with their role-name password.
    # Use a genuine login rather than role membership or superuser impersonation.
    connection.commit()
    engine = create_engine(connection.engine.url.set(username=role, password=role),
                           hide_parameters=True, poolclass=NullPool)
    try:
        with engine.begin() as principal:
            assert principal.execute(text("SELECT session_user, current_user")).one() == (role, role)
            principal.execute(text("SELECT pg_catalog.set_config('app.current_tenant', :tenant, true)"),
                              {"tenant": str(tenant_id) if tenant_id else ""})
            yield principal
    finally:
        engine.dispose()


def _activate(connection, tenant_id, *, nomination_id=None, person_id=None, course_id=None, limit=None, actor_id=None):
    return connection.execute(text("""
        SELECT * FROM public.activate_eligible_facilitator_nominations(
          :tenant, :nomination, :person, :course, :limit, :actor)
    """), {"tenant": tenant_id, "nomination": nomination_id, "person": person_id,
           "course": course_id, "limit": limit, "actor": actor_id}).all()


def _seed(connection, *, status="active", complete=True, requirements=True, nomination_status="pending"):
    db = Session(bind=connection, expire_on_commit=False)
    tenant = Tenant(slug=f"a010-{uuid4().hex}", name="a010 rehearsal")
    db.add(tenant)
    db.flush()
    connection.info.setdefault("a010_tenants", []).append(tenant.id)
    actor = _person(db, tenant.id, f"actor-{uuid4().hex}@example.test")
    nominee = _person(db, tenant.id, f"nominee-{uuid4().hex}@example.test")
    db.execute(text("UPDATE public.academy_account_profiles SET status=:status WHERE party_id=:party"),
               {"status": status, "party": nominee.id})
    cohort = _cohort(db, tenant.id, "a010 cohort")
    course = _course(db, tenant.id, f"a010-{uuid4().hex}")
    offering = _offering(db, tenant.id, cohort.id, course.id)
    nomination = FacilitatorNomination(tenant_id=tenant.id, person_id=nominee.id, nominated_by_person_id=actor.id,
                                       scope_type="course", offering_id=offering.id, status=nomination_status)
    db.add(nomination)
    db.flush()
    if requirements:
        db.add(FacilitatorRequirement(tenant_id=tenant.id, nomination_id=nomination.id, course_id=course.id))
    if complete:
        db.add(CourseCompletion(tenant_id=tenant.id, person_id=nominee.id, course_id=course.id,
                                status="completed", pct=1.0))
    db.flush()
    return db, tenant, actor, nominee, cohort, course, offering, nomination


def test_a010_catalog_exact_runtime_capability_and_worker_boundary(assembly_db):
    connection = assembly_db
    owner, definer, settings, kind, parallel, strict, defaults = connection.execute(text("""
        SELECT pg_catalog.pg_get_userbyid(proowner), prosecdef, proconfig, provolatile,
               proparallel, proisstrict, pronargdefaults
        FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(:function)
    """), {"function": FUNCTION}).one()
    assert (owner, definer, settings, kind, parallel, strict, defaults) == (
        "app_admin", True, ["search_path=pg_catalog"], "v", "u", False, 5)
    acl = connection.execute(text("""
        SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
               a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_proc p,
        LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
        WHERE p.oid=pg_catalog.to_regprocedure(:function) AND a.grantee<>p.proowner
    """), {"function": FUNCTION}).all()
    assert set(acl) == {(role, "EXECUTE", False) for role in RUNTIME_ROLES}
    for table in ("facilitator_nominations", "facilitator_requirements"):
        assert connection.execute(text("""
            SELECT relrowsecurity, relforcerowsecurity FROM pg_catalog.pg_class
            WHERE oid=pg_catalog.to_regclass(:table)
        """), {"table": f"public.{table}"}).one() == (True, True)
        grants = connection.execute(text("""
            SELECT grantee, privilege_type FROM information_schema.table_privileges
            WHERE table_schema='public' AND table_name=:table AND grantee<>'app_admin'
        """), {"table": table}).all()
        assert set(grants) == {(role, privilege) for role in ("app_user", "platform_api")
                               for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE")}
    for table in ("facilitator_nominations", "facilitator_requirements", "audit_events"):
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            assert not connection.scalar(text("SELECT has_table_privilege('academy_lab_worker', :table, :privilege)"),
                                         {"table": f"public.{table}", "privilege": privilege})
    with Operations.context(MigrationContext.configure(connection)):
        with pytest.raises(ValueError, match="already exist"):
            _migration().upgrade()


@pytest.mark.parametrize("role", RUNTIME_ROLES)
@pytest.mark.parametrize("user_actor", (True, False))
def test_a010_real_principal_activation_has_atomic_canonical_audit_and_is_idempotent(runtime_db, role, user_actor):
    connection = runtime_db
    db, tenant, actor, nominee, _, _, _, nomination = _seed(connection)
    try:
        # Hostile search_path and temporary names cannot redirect qualified SQL.
        with _principal(connection, role, tenant.id) as principal:
            principal.execute(text("CREATE TEMP TABLE notifications (id uuid)"))
            principal.execute(text("SET LOCAL search_path=pg_temp,public"))
            assert _activate(principal, tenant.id, nomination_id=nomination.id,
                             actor_id=actor.id if user_actor else None) == [(nomination.id, True)]
            assert _activate(principal, tenant.id, nomination_id=nomination.id,
                             actor_id=actor.id if user_actor else None) == [(nomination.id, False)]
            assert principal.scalar(text("SELECT count(*) FROM pg_temp.notifications")) == 0
        audit = connection.execute(text("""
            SELECT actor_type, actor_id, actor_party_id, source_application, action, entity_type
            FROM public.audit_events WHERE entity_id=:id
        """), {"id": str(nomination.id)}).one()
        assert audit == ("user" if user_actor else "system", str(actor.id) if user_actor else "facilitator_activation",
                         actor.id if user_actor else None, "dotmac_academy_app", "facilitator_nomination.activate",
                         "facilitator_nomination")
        assert connection.scalar(text("SELECT count(*) FROM public.notifications WHERE person_id=:person"),
                                 {"person": nominee.id}) == 1
    finally:
        db.close()


@pytest.mark.parametrize("changes", (
    {"status": "disabled"}, {"complete": False}, {"requirements": False}, {"nomination_status": "revoked"},
))
def test_a010_missing_eligibility_never_activates(runtime_db, changes):
    connection = runtime_db
    db, tenant, _, nominee, _, _, _, nomination = _seed(connection, **changes)
    try:
        with _principal(connection, "academy_lab_worker", tenant.id) as principal:
            assert _activate(principal, tenant.id, nomination_id=nomination.id) == [(nomination.id, False)]
        assert connection.scalar(text("SELECT count(*) FROM public.notifications WHERE person_id=:id"),
                                 {"id": nominee.id}) == 0
        assert connection.scalar(text("SELECT count(*) FROM public.audit_events WHERE entity_id=:id"),
                                 {"id": str(nomination.id)}) == 0
    finally:
        db.close()


@pytest.mark.parametrize("attack", ("absent_tenant", "wrong_tenant", "actor_tenant", "actor_provenance",
                                   "actor_automated", "selector", "zero_limit", "oversize_limit"))
def test_a010_selectors_tenant_and_actor_provenance_refuse(runtime_db, attack):
    connection = runtime_db
    db, tenant, actor, nominee, _, course, _, nomination = _seed(connection)
    try:
        other = Tenant(slug=f"a010-other-{uuid4().hex}", name="Other")
        db.add(other)
        db.flush()
        connection.info.setdefault("a010_tenants", []).append(other.id)
        foreign_actor = _person(db, other.id, f"foreign-{uuid4().hex}@example.test")
        args = {"nomination_id": nomination.id, "actor_id": actor.id}
        context_tenant = tenant.id
        if attack == "absent_tenant":
            context_tenant = None
        elif attack == "wrong_tenant":
            context_tenant = other.id
        elif attack == "actor_tenant":
            args["actor_id"] = foreign_actor.id
        elif attack == "actor_provenance":
            args["actor_id"] = nominee.id
        elif attack == "actor_automated":
            args = {"limit": 10, "actor_id": actor.id}
        elif attack == "selector":
            args["course_id"] = course.id
        else:
            args = {"limit": 0 if attack == "zero_limit" else 1001}
        with pytest.raises(DBAPIError) as refusal:
            with _principal(connection, "app_user", context_tenant) as principal:
                _activate(principal, tenant.id, **args)
        assert refusal.value.orig.sqlstate == ("42501" if attack in ("absent_tenant", "wrong_tenant") else "22023")
        assert connection.scalar(text("SELECT status FROM public.facilitator_nominations WHERE id=:id"),
                                 {"id": nomination.id}) == "pending"
    finally:
        db.close()


def test_a010_cross_tenant_and_nonperson_foreign_keys_and_rls(runtime_db):
    connection = runtime_db
    db, tenant, _, _, _, _, _, nomination = _seed(connection)
    try:
        other = Tenant(slug=f"a010-other-{uuid4().hex}", name="Other")
        db.add(other)
        db.flush()
        connection.info.setdefault("a010_tenants", []).append(other.id)
        person = _person(db, other.id, f"other-{uuid4().hex}@example.test")
        cohort = _cohort(db, other.id, "other")
        course = _course(db, other.id, f"other-{uuid4().hex}")
        offering = _offering(db, other.id, cohort.id, course.id)
        organization = Party(tenant_id=tenant.id, party_type=PartyType.organization, display_name="Not a person")
        db.add(organization)
        db.flush()
        for column, value in (("person_id", person.id), ("nominated_by_person_id", person.id),
                              ("offering_id", offering.id), ("person_id", organization.id),
                              ("nominated_by_person_id", organization.id)):
            with connection.begin_nested() as savepoint:
                with pytest.raises(DBAPIError) as refusal:
                    connection.execute(
                        text(f"UPDATE public.facilitator_nominations SET {column}=:value WHERE id=:id"),  # noqa: S608 -- closed column tuple
                                       {"value": value, "id": nomination.id})
                assert refusal.value.orig.sqlstate == "23503"
                savepoint.rollback()
        with connection.begin_nested() as savepoint:
            with pytest.raises(DBAPIError) as refusal:
                connection.execute(text("""
                    UPDATE public.facilitator_nominations
                    SET scope_type='cohort', offering_id=NULL, cohort_id=:cohort WHERE id=:id
                """), {"cohort": cohort.id, "id": nomination.id})
            assert refusal.value.orig.sqlstate == "23503"
            savepoint.rollback()
        with connection.begin_nested() as savepoint:
            with pytest.raises(DBAPIError) as refusal:
                connection.execute(text("""
                    UPDATE public.facilitator_requirements SET course_id=:course WHERE nomination_id=:id
                """), {"course": course.id, "id": nomination.id})
            assert refusal.value.orig.sqlstate == "23503"
            savepoint.rollback()
        with _principal(connection, "app_user", other.id) as principal:
            assert principal.scalar(text("SELECT count(*) FROM public.facilitator_nominations")) == 0
            assert _activate(principal, other.id, nomination_id=nomination.id) == []
    finally:
        db.close()


def test_a010_grandfather_requires_actual_instructor_grant_and_preserves_enrollment(fresh_target, monkeypatch):
    from app.maintenance.fresh_product import rehearse_fresh_composed_entry

    connection = fresh_target
    original_upgrade = command.upgrade
    evidence = {}

    class StageInspected(Exception):
        pass

    def seeded_upgrade(cfg, revision, *args, **kwargs):
        if revision != "heads":
            return original_upgrade(cfg, revision, *args, **kwargs)
        original_upgrade(cfg, "a009_applicant_bank_version_pin")
        db = Session(bind=connection, expire_on_commit=False)
        try:
            expected = set()
            for label in ("first", "other"):
                tenant = Tenant(slug=f"grandfather-{label}-{uuid4().hex}", name=label)
                db.add(tenant)
                db.flush()
                eligible = _person(db, tenant.id, f"eligible-{uuid4().hex}@example.test")
                # Original grant grandfathering did not impose current profile status.
                db.execute(text("UPDATE public.academy_account_profiles SET status='disabled' WHERE party_id=:id"),
                           {"id": eligible.id})
                orphan = _person(db, tenant.id, f"orphan-{uuid4().hex}@example.test")
                cohort = _cohort(db, tenant.id, label)
                role = Role(tenant_id=tenant.id, slug="instructor", name="Instructor")
                db.add(role)
                db.flush()
                db.add(PartyRoleGrant(tenant_id=tenant.id, party_id=eligible.id, role_id=role.id))
                for person in (eligible, orphan):
                    db.add(Enrollment(tenant_id=tenant.id, cohort_id=cohort.id, person_id=person.id,
                                      role_in_cohort="instructor", status="active"))
                expected.add((tenant.id, eligible.id, cohort.id, "active", "legacy_grandfathered"))
            db.flush()
            before = connection.execute(text("SELECT * FROM mod_learning.enrollments ORDER BY id")).all()
            original_upgrade(cfg, REVISION)
            evidence["rows"] = set(connection.execute(text("""
                SELECT tenant_id, person_id, cohort_id, status, activation_reason FROM public.facilitator_nominations
            """)).all())
            evidence["expected"] = expected
            evidence["enrollments_unchanged"] = (
                connection.execute(text("SELECT * FROM mod_learning.enrollments ORDER BY id")).all() == before)
            assert connection.scalar(text("SELECT count(*) FROM public.facilitator_requirements")) == 0
            assert connection.scalar(text("SELECT count(*) FROM public.notifications")) == 0
            assert connection.scalar(text(
                "SELECT count(*) FROM public.audit_events WHERE action='facilitator_nomination.activate'")) == 0
        finally:
            db.close()
        raise StageInspected

    monkeypatch.setattr(command, "upgrade", seeded_upgrade)
    with pytest.raises(StageInspected):
        rehearse_fresh_composed_entry(connection, decision_ref="C4 staged a010 grandfather-only proof")
    assert evidence["rows"] == evidence["expected"]
    assert evidence["enrollments_unchanged"]


def test_a010_fixed_sql_action_has_installed_manifest_declaration():
    from app.owner_composition import compose_migration_owner_declarations

    actions = {action for owner in compose_migration_owner_declarations() for action in owner.audit_actions}
    assert "facilitator_nomination.activate" in actions


def test_a010_missing_profile_and_bounded_sweep_order(runtime_db):
    connection = runtime_db
    seeded = [_seed(connection)]
    try:
        # Put three nominees in one tenant/scope so the sweep can demonstrate
        # that ineligible earlier rows do not consume its eligible-row limit.
        db, tenant, actor, nominee, cohort, course, offering, first = seeded[0]
        candidates = [first]
        for _ in range(2):
            person = _person(db, tenant.id, f"sweep-{uuid4().hex}@example.test")
            nomination = FacilitatorNomination(tenant_id=tenant.id, person_id=person.id,
                                               nominated_by_person_id=actor.id, scope_type="course",
                                               offering_id=offering.id, status="pending")
            db.add(nomination)
            db.flush()
            db.add(FacilitatorRequirement(tenant_id=tenant.id, nomination_id=nomination.id, course_id=course.id))
            db.add(CourseCompletion(tenant_id=tenant.id, person_id=person.id, course_id=course.id,
                                    status="completed", pct=1.0))
            candidates.append(nomination)
        db.flush()
        connection.execute(text("DELETE FROM public.academy_account_profiles WHERE party_id=:id"), {"id": nominee.id})
        ordered = sorted(candidates[1:], key=lambda row: (row.created_at, row.id))
        with _principal(connection, "academy_lab_worker", tenant.id) as principal:
            assert _activate(principal, tenant.id, nomination_id=first.id) == [(first.id, False)]
            assert _activate(principal, tenant.id, limit=1) == [(ordered[0].id, True)]
            assert _activate(principal, tenant.id, limit=1) == [(ordered[1].id, True)]
            assert _activate(principal, tenant.id, limit=1) == []
        audits = connection.execute(text("""
            SELECT actor_type, actor_id, actor_party_id FROM public.audit_events WHERE tenant_id=:tenant
        """), {"tenant": tenant.id}).all()
        assert audits == [("system", "facilitator_activation", None)] * 2
    finally:
        for row in seeded:
            row[0].close()


def test_a010_statement_failure_rolls_back_status_notification_and_audit(runtime_db):
    connection = runtime_db
    db, tenant, actor, nominee, _, _, _, nomination = _seed(connection)
    try:
        connection.execute(text("""
            CREATE FUNCTION public.a010_test_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'a010 synthetic audit failure'; END; $$
        """))
        connection.execute(text("""
            CREATE TRIGGER a010_test_reject_audit BEFORE INSERT ON public.audit_events
            FOR EACH ROW EXECUTE FUNCTION public.a010_test_reject_audit()
        """))
        with pytest.raises(DBAPIError, match="a010 synthetic audit failure"):
            with _principal(connection, "academy_lab_worker", tenant.id) as principal:
                _activate(principal, tenant.id, nomination_id=nomination.id, actor_id=actor.id)
        assert connection.scalar(text("SELECT status FROM public.facilitator_nominations WHERE id=:id"),
                                 {"id": nomination.id}) == "pending"
        assert connection.scalar(text("SELECT count(*) FROM public.notifications WHERE person_id=:id"),
                                 {"id": nominee.id}) == 0
        assert connection.scalar(text("SELECT count(*) FROM public.audit_events WHERE entity_id=:id"),
                                 {"id": str(nomination.id)}) == 0
    finally:
        connection.rollback()
        connection.execute(text("DROP TRIGGER IF EXISTS a010_test_reject_audit ON public.audit_events"))
        connection.execute(text("DROP FUNCTION IF EXISTS public.a010_test_reject_audit()"))
        connection.commit()
        db.close()


def test_a010_skip_locked_and_concurrent_activation_emit_one_consequence(runtime_db):
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    connection = runtime_db
    db, tenant, _, nominee, _, _, _, nomination = _seed(connection)
    worker = create_engine(connection.engine.url.set(username="academy_lab_worker", password="academy_lab_worker"),
                           hide_parameters=True, poolclass=NullPool)
    try:
        connection.commit()
        connection.execute(text("SELECT id FROM public.facilitator_nominations WHERE id=:id FOR UPDATE"),
                           {"id": nomination.id})
        with worker.begin() as principal:
            principal.execute(text("SET LOCAL statement_timeout='15s'"))
            principal.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"),
                              {"tenant": str(tenant.id)})
            assert _activate(principal, tenant.id, limit=1) == []
        connection.rollback()
        barrier = Barrier(2)

        def race():
            with worker.begin() as principal:
                assert principal.execute(text("SELECT session_user, current_user")).one() == (
                    "academy_lab_worker", "academy_lab_worker")
                principal.execute(text("SET LOCAL statement_timeout='15s'"))
                principal.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"),
                                  {"tenant": str(tenant.id)})
                barrier.wait(timeout=15)
                return _activate(principal, tenant.id, nomination_id=nomination.id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(race)
            second = executor.submit(race)
            results = [first.result(timeout=30), second.result(timeout=30)]
        assert sorted(rows[0][1] for rows in results) == [False, True]
        assert all(rows[0][0] == nomination.id for rows in results)
        assert connection.scalar(text("SELECT count(*) FROM public.notifications WHERE person_id=:id"),
                                 {"id": nominee.id}) == 1
        assert connection.scalar(text("SELECT count(*) FROM public.audit_events WHERE entity_id=:id"),
                                 {"id": str(nomination.id)}) == 1
    finally:
        worker.dispose()
        db.close()


def test_a010_preflight_refuses_real_runtime_owner():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    raw = os.environ.get("TEST_DATABASE_URL")
    assert raw, "CI must provision the genuine app_user login"
    url = make_url(raw)
    assert url.drivername == "postgresql+psycopg" and url.username == "app_user"
    engine = create_engine(url, hide_parameters=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT session_user, current_user")).one() == ("app_user", "app_user")
            with Operations.context(MigrationContext.configure(connection)):
                with pytest.raises(ValueError, match="requires app_admin"):
                    _migration().upgrade()
    finally:
        engine.dispose()
