"""Genuine frozen62 PostgreSQL structural canaries; AUTHORED, NOT RUN.

The positive is the actual a5 frozen62 replay as app_admin. It deliberately ends
at Unsupported until the separately reviewed frozen-source PG rendering oracle
closes the hosted gate. No fake catalog or current ORM is a positive substitute.
"""

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError

from app.maintenance import retained_schema as retained
from tests.fixtures.kernel_identity_entry.rehearsal import FIXTURE, LEGACY_HEAD, verify_legacy_source
from tests.test_kernel_identity_entry import entry_transaction, legacy_engine

assert legacy_engine


def _structurally_inspected(connection):
    packet = retained._observe_historical_catalog(connection)
    retained._check_structure(packet)
    retained._check_security(packet)
    return packet


def test_genuine_full_frozen62_source_and_historical_catalog(legacy_engine):
    verify_legacy_source()
    retained._verify_frozen_source(FIXTURE / "alembic/versions")
    with entry_transaction(legacy_engine) as connection:
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
def test_planted_structural_security_drift_is_refused_before_unsupported(legacy_engine, statements):
    with entry_transaction(legacy_engine) as connection:
        _structurally_inspected(connection)
        for statement in statements:
            connection.execute(sa.text(statement))
        with pytest.raises(retained.RetainedSchemaRefused) as error:
            retained._verify_historical_retained_schema(connection)
        assert type(error.value) is retained.RetainedSchemaRefused


def test_fk_validation_and_deferrability_are_fixed(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
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


def test_role_context_cannot_hide_rows_or_supply_a_positive_packet(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
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


def test_real_app_user_cannot_insert_worker_state(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
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


def test_real_constraints_reject_bad_worker_values(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
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


def test_unsupported_expressions_cannot_issue_admission(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
        # An identically named, validated but wrong CHECK is deliberately NOT
        # certified by the intermediate structural pass. Until hosted rendering
        # is pinned, even an otherwise natural replay has the same refusal gate.
        connection.execute(sa.text("ALTER TABLE public.lab_operations DROP CONSTRAINT ck_lab_operations_kind"))
        connection.execute(
            sa.text("ALTER TABLE public.lab_operations ADD CONSTRAINT ck_lab_operations_kind CHECK(true)")
        )
        with pytest.raises(retained.RetainedSchemaUnsupported):
            retained._verify_historical_retained_schema(connection)


def test_catalog_packet_can_be_reviewed_as_source_only_artifact(legacy_engine, tmp_path, record_property):
    verify_legacy_source()
    retained._verify_frozen_source(FIXTURE / "alembic/versions")
    with entry_transaction(legacy_engine) as connection:
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


def test_real_request_columns_and_defaults_then_worker_settlement(legacy_engine):
    with entry_transaction(legacy_engine) as connection:
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
