"""Genuine frozen62 PostgreSQL structural canaries; AUTHORED, NOT RUN.

The positive is the actual a5 frozen62 replay as app_admin. It deliberately ends
at Unsupported until the separately reviewed frozen-source PG rendering oracle
closes the hosted gate. No fake catalog or current ORM is a positive substitute.
"""

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from alembic import command
from alembic.script import ScriptDirectory
from app.maintenance import retained_schema as retained
from tests.fixtures.kernel_identity_entry.rehearsal import FIXTURE, LEGACY_HEAD, config_for, verify_legacy_source
from tests.test_kernel_identity_entry import _seed_populated_legacy, entry_transaction


@pytest.fixture(scope="module")
def retained_engine(tmp_path_factory):
    """Replay genuine frozen62 once into a separately provisioned empty database."""
    assert os.environ.get("CI") == "true", "retained-schema rehearsals are hosted CI only"
    url = os.environ.get("RETAINED_SCHEMA_DATABASE_URL")
    assert url, "CI must provision RETAINED_SCHEMA_DATABASE_URL"
    target = make_url(url)
    assert target.get_backend_name() == "postgresql" and target.database
    for name in (
        "KERNEL_ENTRY_DATABASE_URL",
        "TEST_DATABASE_URL",
        "TEST_MIGRATION_DATABASE_URL",
        "MIGRATION_DATABASE_URL",
        "DATABASE_URL",
        "TEST_LAB_WORKER_DATABASE_URL",
        "PLATFORM_DATABASE_URL",
    ):
        other = os.environ.get(name)
        if other:
            assert target.database != make_url(other).database, "retained replay DB must be separate"
    verify_legacy_source()
    retained._verify_frozen_source(FIXTURE / "alembic/versions")
    engine = sa.create_engine(url, hide_parameters=True, echo=False, future=True)
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.text("""
                SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
            """)
                )
                == 0
            ), "retained replay DB must start empty"
            assert (
                connection.scalar(
                    sa.text("""
                SELECT count(*) FROM pg_roles WHERE rolname IN
                ('app_admin','app_user','platform_api','academy_lab_worker',
                 'outbox_dispatcher','platform_outbox_dispatcher')
            """)
                )
                == 6
            ), "CI must provision unchanged Kernel/legacy cluster roles"
            assert connection.scalar(sa.text("SELECT rolbypassrls FROM pg_roles WHERE rolname='app_admin'"))
            connection.rollback()
            with connection.begin():
                connection.execute(sa.text("SET ROLE app_admin"))
            applied = []
            cfg = config_for(
                connection, FIXTURE / "alembic/versions", tmp_path_factory.mktemp("retained-entry-env"), applied
            )
            scripts = ScriptDirectory.from_config(cfg)
            assert scripts.get_heads() == [LEGACY_HEAD]
            command.upgrade(cfg, "heads")
            assert len(applied) == 62
            assert {item.revision for item in applied} == {item.revision for item in scripts.walk_revisions()}
            assert not connection.in_transaction()
            with connection.begin():
                _seed_populated_legacy(connection)
        yield engine
    finally:
        engine.dispose()


def _structurally_inspected(connection):
    packet = retained._observe_historical_catalog(connection)
    retained._check_structure(packet)
    retained._check_security(packet)
    return packet


def test_genuine_full_frozen62_source_and_historical_catalog(retained_engine):
    verify_legacy_source()
    retained._verify_frozen_source(FIXTURE / "alembic/versions")
    with entry_transaction(retained_engine) as connection:
        assert tuple(connection.scalars(sa.text("SELECT version_num FROM public.alembic_version"))) == (LEGACY_HEAD,)
        packet = _structurally_inspected(connection)
        assert len(packet["relations"]) == 11
        assert len(packet["columns"]) == 166
        assert len(packet["indexes"]) == 49
        assert len(packet["constraints"]) == 42
        assert "account_tokens" not in retained._NAMES
        assert not any(r[0] == "platform_settings" for r in packet["policies"])
        before = packet
        with pytest.raises(retained.RetainedSchemaUnsupported):
            retained._verify_historical_retained_schema(connection)
        assert retained._observe_historical_catalog(connection) == before


@pytest.mark.parametrize(
    "statements",
    (
        ("ALTER TABLE public.applicants DROP COLUMN phone",),
        ("ALTER TABLE public.applicants ADD COLUMN planted_extra text",),
        ("ALTER TABLE public.lab_instances ALTER COLUMN runtime_presence DROP NOT NULL",),
        ("ALTER TABLE public.lab_instances ALTER COLUMN runtime_presence SET DEFAULT 'present'",),
        ("ALTER TABLE public.applicants ALTER COLUMN email TYPE varchar(255)",),
        (
            "ALTER TABLE public.applicants ADD CONSTRAINT planted_person_fk FOREIGN KEY(person_id) REFERENCES public.people(id)",
        ),
        (
            "ALTER TABLE public.applicants DROP CONSTRAINT fk_applicants_tenant_assessment_bank",
            "ALTER TABLE public.applicants ADD CONSTRAINT fk_applicants_tenant_assessment_bank "
            "FOREIGN KEY(tenant_id,assessment_bank_id) REFERENCES public.question_banks(tenant_id,id) ON DELETE CASCADE",
        ),
        (
            "ALTER TABLE public.onboarding_tasks DROP CONSTRAINT fk_onboarding_tasks_tenant_applicant",
            "ALTER TABLE public.onboarding_tasks ADD CONSTRAINT fk_onboarding_tasks_tenant_applicant "
            "FOREIGN KEY(tenant_id,applicant_id) REFERENCES public.applicants(tenant_id,id) ON DELETE NO ACTION",
        ),
        ("DROP INDEX public.uq_applicants_tenant_local_email",),
        (
            "DROP INDEX public.uq_applicants_tenant_local_email",
            "CREATE UNIQUE INDEX uq_applicants_tenant_local_email ON public.applicants(tenant_id,email) WHERE external_ref IS NOT NULL",
        ),
        ("ALTER TABLE public.applicants NO FORCE ROW LEVEL SECURITY",),
        ("ALTER TABLE public.applicants DISABLE ROW LEVEL SECURITY",),
        ("DROP POLICY applicants_tenant_isolation ON public.applicants",),
        ("ALTER POLICY applicants_tenant_isolation ON public.applicants USING (true)",),
        ("CREATE POLICY planted_policy ON public.applicants USING (true)",),
        ("ALTER TABLE public.platform_settings ENABLE ROW LEVEL SECURITY",),
        ("GRANT INSERT(state) ON public.lab_operations TO app_user",),
        ("GRANT UPDATE ON public.lab_instances TO app_user",),
        ("GRANT SELECT ON public.applicants TO PUBLIC",),
        ("REVOKE INSERT(id) ON public.lab_operations FROM app_user",),
        (
            "ALTER TABLE public.lab_instances DROP CONSTRAINT ck_lab_instances_runtime_presence",
            "ALTER TABLE public.lab_instances ADD CONSTRAINT ck_lab_instances_runtime_presence "
            "CHECK(runtime_presence IN ('absent','present','unknown')) NOT VALID",
        ),
    ),
)
def test_planted_structural_security_drift_is_refused_before_unsupported(retained_engine, statements):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        for statement in statements:
            connection.execute(sa.text(statement))
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_fk_validation_and_deferrability_are_fixed(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        connection.execute(
            sa.text(
                "ALTER TABLE public.applicants ALTER CONSTRAINT "
                "fk_applicants_tenant_assessment_bank DEFERRABLE INITIALLY DEFERRED"
            )
        )
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_role_context_cannot_hide_rows_or_supply_a_positive_packet(retained_engine):
    with entry_transaction(retained_engine) as connection:
        original = _structurally_inspected(connection)
        # Genuine source population is visible to the bypass admin. A restricted
        # request role without tenant context sees zero. Counts are test-only,
        # never part of the verifier's read-only catalog packet or its authority.
        tenant = str(uuid4())
        connection.execute(
            sa.text("INSERT INTO public.tenants(id,slug,name) VALUES(:id,:slug,'Retained test')"),
            {"id": tenant, "slug": "retained-" + tenant},
        )
        connection.execute(
            sa.text(
                "INSERT INTO public.applicants(id,tenant_id,email,first_name,last_name) "
                "VALUES(:id,:tenant,'retained@example.invalid','Retained','Test')"
            ),
            {"id": str(uuid4()), "tenant": tenant},
        )
        assert connection.scalar(sa.text("SELECT count(*) FROM public.applicants")) > 0
        connection.execute(sa.text("SELECT set_config('app.current_tenant','',true)"))
        connection.execute(sa.text("SET LOCAL ROLE app_user"))
        assert connection.scalar(sa.text("SELECT count(*) FROM public.applicants")) == 0
        with pytest.raises(retained.RetainedSchemaRefused):
            retained._verify_historical_retained_schema(connection)
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        assert retained._observe_historical_catalog(connection) == original
        with pytest.raises(TypeError):
            retained._verify_historical_retained_schema(connection, original)


def test_real_app_user_cannot_insert_worker_state(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        connection.execute(sa.text("SET LOCAL ROLE app_user"))
        with pytest.raises(DBAPIError), connection.begin_nested():
            connection.execute(
                sa.text(
                    "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind,state) "
                    "VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'deploy','claimed')"
                )
            )
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        _structurally_inspected(connection)


def test_real_constraints_reject_bad_worker_values(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        tenant = connection.scalar(sa.text("SELECT id FROM public.tenants ORDER BY id LIMIT 1"))
        instance = str(uuid4())
        connection.execute(
            sa.text(
                "INSERT INTO public.lab_instances(id,tenant_id,activity_id,person_id,instance_name) "
                "VALUES(:id,:tenant,:activity,:person,:name)"
            ),
            {
                "id": instance,
                "tenant": tenant,
                "activity": str(uuid4()),
                "person": str(uuid4()),
                "name": "retained-" + instance,
            },
        )
        connection.execute(sa.text("SET LOCAL ROLE academy_lab_worker"))
        for kind, origin, precondition in (
            ("unknown", None, None),
            ("deploy", "runtime_repair", None),
            ("destroy", "runtime_repair", "present"),
        ):
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(
                    sa.text(
                        "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind,origin,runtime_precondition) "
                        "VALUES(gen_random_uuid(),:tenant,:instance,:kind,:origin,:precondition)"
                    ),
                    {
                        "tenant": tenant,
                        "instance": instance,
                        "kind": kind,
                        "origin": origin,
                        "precondition": precondition,
                    },
                )
        with pytest.raises(DBAPIError), connection.begin_nested():
            connection.execute(
                sa.text("UPDATE public.lab_instances SET runtime_presence='invented' WHERE id=:id"), {"id": instance}
            )
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        _structurally_inspected(connection)


def test_unsupported_expressions_cannot_issue_admission(retained_engine):
    with entry_transaction(retained_engine) as connection:
        # Same name and validation cannot hide a wrong expression. Candidate
        # source-rendered CHECK pins refuse this before the final unsupported gate.
        connection.execute(sa.text("ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_kind"))
        connection.execute(
            sa.text("ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_kind CHECK(true)")
        )
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_catalog_packet_can_be_reviewed_as_source_only_artifact(retained_engine, tmp_path, record_property):
    verify_legacy_source()
    retained._verify_frozen_source(FIXTURE / "alembic/versions")
    with entry_transaction(retained_engine) as connection:
        packet = retained._observe_historical_catalog(connection)
        # Nothing here claims the rendering contract passed. This packet comes
        # exclusively from the immutable frozen replay fixture, never a proposed
        # adopted/live schema, and contains only catalog/security observations.
        artifact = {
            "source_only": True,
            "admission_authority": False,
            "unsupported": retained._RENDERING_GATE,
            "frozen62": retained._FROZEN62,
            "catalog": packet,
        }
        destination = Path(tmp_path) / "frozen62-retained-catalog-source-only.json"
        raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
        destination.write_bytes(raw)
        record_property("retained_catalog_artifact", str(destination))
        record_property("retained_catalog_sha256", hashlib.sha256(raw).hexdigest())
        assert len(packet["relations"]) == 11
        assert artifact["admission_authority"] is False


def test_real_request_columns_and_defaults_then_worker_settlement(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        tenant = connection.scalar(sa.text("SELECT id FROM public.tenants ORDER BY id LIMIT 1"))
        instance, operation, person, activity = (str(uuid4()) for _ in range(4))
        connection.execute(sa.text("SELECT set_config('app.current_tenant',:tenant,true)"), {"tenant": str(tenant)})
        connection.execute(sa.text("SET LOCAL ROLE app_user"))
        connection.execute(
            sa.text(
                "INSERT INTO public.lab_instances(id,tenant_id,activity_id,person_id,instance_name) "
                "VALUES(:id,:tenant,:activity,:person,:name)"
            ),
            {"id": instance, "tenant": tenant, "activity": activity, "person": person, "name": "retained-" + instance},
        )
        assert connection.execute(
            sa.text("SELECT status,runtime_presence FROM public.lab_instances WHERE id=:id"), {"id": instance}
        ).one() == ("queued", "absent")
        connection.execute(
            sa.text(
                "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind,requested_by) "
                "VALUES(:id,:tenant,:instance,'deploy',:person)"
            ),
            {"id": operation, "tenant": tenant, "instance": instance, "person": person},
        )
        assert connection.execute(
            sa.text("SELECT state,attempts FROM public.lab_operations WHERE id=:id"), {"id": operation}
        ).one() == ("queued", 0)
        # A second real request fails naturally at the partial unique index.
        with pytest.raises(DBAPIError), connection.begin_nested():
            connection.execute(
                sa.text(
                    "INSERT INTO public.lab_operations(id,tenant_id,instance_id,kind) "
                    "VALUES(gen_random_uuid(),:tenant,:instance,'check')"
                ),
                {"tenant": tenant, "instance": instance},
            )
        connection.execute(sa.text("SET LOCAL ROLE academy_lab_worker"))
        connection.execute(
            sa.text("UPDATE public.lab_operations SET state='succeeded' WHERE id=:id"), {"id": operation}
        )
        connection.execute(
            sa.text("UPDATE public.lab_instances SET runtime_presence='present' WHERE id=:id"), {"id": instance}
        )
        assert (
            connection.scalar(
                sa.text("SELECT runtime_presence FROM public.lab_instances WHERE id=:id"), {"id": instance}
            )
            == "present"
        )
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        _structurally_inspected(connection)


def test_check_no_inherit_drift_is_refused(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        connection.execute(sa.text("ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_kind"))
        connection.execute(
            sa.text(
                "ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_kind "
                "CHECK(kind IN ('deploy','destroy','check')) NO INHERIT"
            )
        )
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize(
    "statements",
    (
        (
            "ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_kind",
            "ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_kind "
            "CHECK(kind IN ('deploy','destroy','check','invented'))",
        ),
        (
            "ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_conditional_runtime",
            "ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_conditional_runtime CHECK "
            "((origin IS NULL AND runtime_precondition IS NULL) OR "
            "(kind='deploy' AND origin='runtime_repair' AND runtime_precondition='absent') OR "
            "(kind='destroy' AND origin='runtime_cleanup' AND runtime_precondition='present'))",
        ),
        (
            "DROP INDEX public.uq_lab_operations_open_per_instance",
            "CREATE UNIQUE INDEX uq_lab_operations_open_per_instance ON public.lab_operations(instance_id) "
            "WHERE state IN ('queued','claimed','failed')",
        ),
        ("ALTER TABLE public.email_outbox ALTER COLUMN payload SET DEFAULT '[]'::jsonb",),
        ("ALTER TABLE public.applicants ALTER COLUMN assessment_result_version DROP DEFAULT",),
        (
            "DROP INDEX public.uq_applicants_tenant_local_email",
            "CREATE UNIQUE INDEX uq_applicants_tenant_local_email ON public.applicants "
            "(tenant_id,email varchar_pattern_ops) WHERE external_ref IS NULL",
        ),
        (
            "DROP INDEX public.ix_applicants_status",
            'CREATE INDEX ix_applicants_status ON public.applicants(tenant_id,status COLLATE "C")',
        ),
        ('ALTER TABLE public.applicants ALTER COLUMN phone TYPE varchar(40) COLLATE "C"',),
    ),
)
def test_rendering_semantic_drift_is_refused(retained_engine, statements):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        for statement in statements:
            connection.execute(sa.text(statement))
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize(
    "setting",
    (
        "SET LOCAL quote_all_identifiers=on",
        "SET LOCAL standard_conforming_strings=off",
        "SET LOCAL search_path=public",
    ),
)
def test_unknown_rendering_context_is_unsupported(retained_engine, setting):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        connection.execute(sa.text(setting))
        with pytest.raises(retained.RetainedSchemaUnsupported):
            retained._verify_historical_retained_schema(connection)


def test_catalog_observes_candidate_rendering_context_without_admission(retained_engine):
    with entry_transaction(retained_engine) as connection:
        packet = retained._observe_historical_catalog(connection)
        assert len(packet["rendering_context"]) == 1
        context = packet["rendering_context"][0]
        assert len(context) == 6
        assert type(context[0]) is int and context[1]
        retained._check_rendering_context(packet)
        with pytest.raises(retained.RetainedSchemaUnsupported):
            retained._verify_historical_retained_schema(connection)


@pytest.mark.parametrize(
    "statements",
    (
        (
            "CREATE OR REPLACE FUNCTION public.app_current_tenant_id() RETURNS uuid LANGUAGE plpgsql STABLE "
            "AS $$ BEGIN RETURN NULL; END; $$",
        ),
        (
            "CREATE FUNCTION public.app_current_tenant_id(integer) RETURNS uuid LANGUAGE sql STABLE "
            "AS $$ SELECT NULL::uuid $$",
        ),
        ("ALTER FUNCTION public.app_current_tenant_id() SECURITY DEFINER",),
        ("ALTER FUNCTION public.app_current_tenant_id() STRICT",),
        ("ALTER FUNCTION public.app_current_tenant_id() VOLATILE",),
        ("ALTER FUNCTION public.app_current_tenant_id() PARALLEL SAFE",),
        ("ALTER FUNCTION public.app_current_tenant_id() SET search_path=public",),
        ("ALTER FUNCTION public.app_current_tenant_id() COST 1",),
        ("REVOKE EXECUTE ON FUNCTION public.app_current_tenant_id() FROM PUBLIC",),
        ("REVOKE EXECUTE ON FUNCTION public.app_current_tenant_id() FROM app_user",),
        ("GRANT EXECUTE ON FUNCTION public.app_current_tenant_id() TO academy_lab_worker",),
        ("GRANT EXECUTE ON FUNCTION public.app_current_tenant_id() TO app_user WITH GRANT OPTION",),
    ),
)
def test_tenant_helper_source_signature_attributes_and_acl_drift_is_refused(retained_engine, statements):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        for statement in statements:
            connection.execute(sa.text(statement))
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_tenant_helper(packet)
        assert type(error.value) is retained.RetainedSchemaRefused
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_natural_helper_public_execute_body_and_policy_dependency_closure(retained_engine):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        helper_oid = retained._check_tenant_helper(packet)
        assert packet["tenant_function_source_sha256"] == ((helper_oid, retained._TENANT_HELPER_BODY_SHA256),)
        assert (helper_oid, "app_admin", "PUBLIC", "EXECUTE", False) in packet["tenant_function_acl"]
        assert all(row[3] is True for row in packet["tenant_function_effective_execute"])
        assert len(packet["policy_dependencies"]) == 50
        retained._check_policy_dependencies(packet)
        tenant = str(uuid4())
        connection.execute(sa.text("SELECT set_config('app.current_tenant',:tenant,true)"), {"tenant": tenant})
        connection.execute(sa.text("SET LOCAL ROLE app_user"))
        assert str(connection.scalar(sa.text("SELECT public.app_current_tenant_id()"))) == tenant
        connection.execute(sa.text("SELECT set_config('app.current_tenant','not-a-uuid',true)"))
        assert connection.scalar(sa.text("SELECT public.app_current_tenant_id()")) is None
        # The worker has effective execution through frozen PUBLIC EXECUTE,
        # without an invented worker-specific helper grant or role inheritance.
        connection.execute(sa.text("SET LOCAL ROLE academy_lab_worker"))
        assert connection.scalar(sa.text("SELECT public.app_current_tenant_id()")) is None
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        _structurally_inspected(connection)
        with pytest.raises(retained.RetainedSchemaUnsupported):
            retained._verify_historical_retained_schema(connection)


def test_policy_dependency_multiplicity_is_not_deduplicated(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        connection.execute(sa.text("ALTER POLICY applicants_tenant_isolation ON public.applicants WITH CHECK (true)"))
        packet = retained._observe_historical_catalog(connection)
        retained._check_tenant_helper(packet)
        # USING retains the same table/tenant/helper endpoints. WITH CHECK now
        # contributes neither a tenant-column nor helper dependency. A set-only
        # comparison would lose this difference in actual catalog multiplicity.
        dependencies = tuple(row for row in packet["policy_dependencies"] if row[0] == "applicants")
        assert len(dependencies) == 3
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_policy_dependencies(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_policies_cannot_retain_an_old_helper_oid_after_source_identical_replacement(retained_engine):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        old_helper_oid = retained._check_tenant_helper(packet)
        connection.execute(sa.text("CREATE SCHEMA retained_helper_shadow AUTHORIZATION app_admin"))
        connection.execute(sa.text("ALTER FUNCTION public.app_current_tenant_id() SET SCHEMA retained_helper_shadow"))
        # Fixed product source body only; no caller input, copied live body or
        # fake catalog. This is a negative endpoint-substitution canary.
        connection.execute(
            sa.text(
                "CREATE FUNCTION public.app_current_tenant_id() RETURNS uuid LANGUAGE plpgsql STABLE "
                "AS $retained$" + retained._TENANT_HELPER_BODY + "$retained$"
            )
        )
        connection.execute(sa.text("GRANT EXECUTE ON FUNCTION public.app_current_tenant_id() TO app_user,platform_api"))
        packet = retained._observe_historical_catalog(connection)
        new_helper_oid = retained._check_tenant_helper(packet)
        assert new_helper_oid != old_helper_oid
        assert (
            sum(row[4] == "pg_catalog.pg_proc" and row[5] == old_helper_oid for row in packet["policy_dependencies"])
            == 20
        )
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_policy_dependencies(packet)
        assert type(error.value) is retained.RetainedSchemaRefused
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_policy_public_role_shared_dependency_drift_is_refused(retained_engine):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        assert not packet["policy_shared_dependencies"]
        connection.execute(sa.text("ALTER POLICY applicants_tenant_isolation ON public.applicants TO app_user"))
        packet = retained._observe_historical_catalog(connection)
        retained._check_tenant_helper(packet)
        assert len(packet["policy_shared_dependencies"]) == 1
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_policy_dependencies(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_natural_source_touching_fk_ri_and_dependency_graph(retained_engine):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        assert len(packet["ri_foreign_keys"]) == 17
        assert len(packet["ri_triggers"]) == 68
        assert len(packet["ri_dependencies"]) == 153
        assert len(packet["ri_relations"]) == 15
        assert len({row[28] for row in packet["ri_parent_keys"]}) == 6
        # These are genuine unrelated frozen owner FKs on external parents.
        # Their classification does not qualify their full constraint family.
        assert packet["ri_external_parent_other_triggers"]
        external = packet["ri_external_parent_other_triggers"]
        assert any(row[1] == row[8] and row[10] == row[9] and row[8] != row[9] for row in external)
        assert any(row[1] == row[9] and row[10] == row[8] and row[8] != row[9] for row in external)
        retained._check_ri_graph(packet)
        with pytest.raises(retained.RetainedSchemaUnsupported):
            retained._verify_historical_retained_schema(connection)


@pytest.mark.parametrize("parent", ("applicants", "lab_instances"))
def test_unexpected_incoming_fk_from_outside_retained_is_refused(retained_engine, parent):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        assert parent in ("applicants", "lab_instances")
        connection.execute(
            sa.text(
                "CREATE TABLE public.retained_incoming_canary (tenant_id uuid, object_id uuid, "
                "FOREIGN KEY (tenant_id,object_id) REFERENCES public." + parent + "(tenant_id,id))"
            )
        )
        packet = retained._observe_historical_catalog(connection)
        assert len(packet["ri_foreign_keys"]) == 18
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize("mode", ("DISABLE", "ENABLE REPLICA", "ENABLE ALWAYS"))
@pytest.mark.parametrize("side", ("child", "parent"))
def test_real_internal_ri_trigger_firing_drift_is_refused(retained_engine, mode, side):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        fk = next(row for row in packet["ri_foreign_keys"] if row[3] == "email_outbox")
        relation_oid = fk[4] if side == "child" else fk[11]
        trigger = next(row for row in packet["ri_triggers"] if row[20] == fk[0] and row[1] == relation_oid)
        assert mode in ("DISABLE", "ENABLE REPLICA", "ENABLE ALWAYS")
        # Real system triggers require the hosted disposable database superuser.
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
        assert trigger[3] in ("email_outbox", "tenants")
        assert trigger[4].startswith("RI_ConstraintTrigger_") and trigger[4].rsplit("_", 1)[1].isdigit()
        connection.execute(sa.text("ALTER TABLE public." + trigger[3] + " " + mode + ' TRIGGER "' + trigger[4] + '"'))
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE pg_catalog.pg_trigger SET tgfoid='pg_catalog.\"RI_FKey_check_upd\"()'::regprocedure " "WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgconstraint=0 WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgconstrindid=0 WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgconstrrelid=tgrelid WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgdeferrable=true WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgtype=7 WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgnargs=1,tgargs=decode('7800','hex') WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgparentid=oid WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgoldtable='planted_transition' WHERE oid=:oid",
    ),
)
def test_real_ri_trigger_catalog_metadata_drift_is_refused(retained_engine, statement):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        trigger = next(row for row in packet["ri_triggers"] if row[3] == "email_outbox" and row[15] == 5)
        # Mutate only a real disposable PG catalog negative, transactionally.
        # This is never a manufactured positive packet or production operation.
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
        connection.execute(sa.text(statement), {"oid": trigger[0]})
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE pg_catalog.pg_constraint SET conindid=0 WHERE oid=:oid",
        "UPDATE pg_catalog.pg_constraint SET conpfeqop=ARRAY['pg_catalog.<>(uuid,uuid)'::regoperator]::oid[] WHERE oid=:oid",
        "UPDATE pg_catalog.pg_constraint SET conppeqop=ARRAY['pg_catalog.<>(uuid,uuid)'::regoperator]::oid[] WHERE oid=:oid",
        "UPDATE pg_catalog.pg_constraint SET conffeqop=ARRAY['pg_catalog.<>(uuid,uuid)'::regoperator]::oid[] WHERE oid=:oid",
    ),
)
def test_real_fk_parent_index_or_equality_operator_drift_is_refused(retained_engine, statement):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        fk = next(row for row in packet["ri_foreign_keys"] if row[3] == "email_outbox")
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
        connection.execute(sa.text(statement), {"oid": fk[0]})
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_external_supporting_parent_key_name_drift_is_refused(retained_engine):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        connection.execute(
            sa.text(
                "ALTER TABLE public.question_banks RENAME CONSTRAINT "
                "uq_question_banks_tenant_id_id TO planted_parent_key"
            )
        )
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize("table,make_internal", (("tenants", False), ("email_outbox", True), ("tenants", True)))
def test_custom_or_unassociated_external_parent_trigger_is_refused(retained_engine, table, make_internal):
    with entry_transaction(retained_engine) as connection:
        _structurally_inspected(connection)
        assert table in ("tenants", "email_outbox")
        connection.execute(
            sa.text(
                "CREATE FUNCTION public.retained_trigger_canary() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$"
            )
        )
        connection.execute(
            sa.text(
                "CREATE TRIGGER retained_trigger_canary AFTER INSERT ON public."
                + table
                + " FOR EACH ROW EXECUTE FUNCTION public.retained_trigger_canary()"
            )
        )
        if make_internal:
            connection.execute(sa.text("SET LOCAL ROLE NONE"))
            assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
            connection.execute(
                sa.text(
                    "UPDATE pg_catalog.pg_trigger SET tgisinternal=true "
                    "WHERE tgrelid=CAST(:table AS regclass) AND tgname='retained_trigger_canary'"
                ),
                {"table": "public." + table},
            )
            connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize("side", ("child", "parent"))
@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE pg_catalog.pg_trigger SET tgconstrrelid=0 WHERE oid=:oid",
        "UPDATE pg_catalog.pg_trigger SET tgconstraint=0 WHERE oid=:oid",
    ),
)
def test_unrelated_external_fk_trigger_association_drift_is_refused(retained_engine, side, statement):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        retained._check_ri_graph(packet)
        trigger = next(
            row
            for row in packet["ri_external_parent_other_triggers"]
            if row[8] != row[9] and row[1] == row[8 if side == "child" else 9]
        )
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
        connection.execute(sa.text(statement), {"oid": trigger[0]})
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        assert any(row[0] == trigger[0] for row in packet["ri_external_parent_other_triggers"])
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_ri_dependency_multiplicity_is_not_deduplicated(retained_engine):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        fk = next(row for row in packet["ri_foreign_keys"] if row[3] == "email_outbox")
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
        connection.execute(
            sa.text(
                "INSERT INTO pg_catalog.pg_depend "
                "SELECT * FROM pg_catalog.pg_depend WHERE classid='pg_catalog.pg_constraint'::regclass "
                "AND objid=:oid AND refclassid='pg_catalog.pg_class'::regclass AND deptype='n' LIMIT 1"
            ),
            {"oid": fk[0]},
        )
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        assert len(packet["ri_dependencies"]) == 154
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused


@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE pg_catalog.pg_index SET indnullsnotdistinct=true WHERE indexrelid=:oid",
        "UPDATE pg_catalog.pg_index SET indisvalid=false WHERE indexrelid=:oid",
        "UPDATE pg_catalog.pg_index SET indimmediate=false WHERE indexrelid=:oid",
    ),
)
def test_real_supporting_parent_index_flag_drift_is_refused(retained_engine, statement):
    with entry_transaction(retained_engine) as connection:
        packet = _structurally_inspected(connection)
        key = next(row for row in packet["ri_parent_keys"] if row[4] == "uq_question_banks_tenant_id_id")
        connection.execute(sa.text("SET LOCAL ROLE NONE"))
        assert connection.scalar(sa.text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
        connection.execute(sa.text(statement), {"oid": key[2]})
        connection.execute(sa.text("SET LOCAL ROLE app_admin"))
        packet = retained._observe_historical_catalog(connection)
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._check_ri_graph(packet)
        assert type(error.value) is retained.RetainedSchemaRefused
