"""Console heartbeat: rate limit, role boundaries, RLS and the idle reaper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.models.assessment import Activity
from app.models.course import Course
from app.models.lab import LabConsoleActivity, LabInstance, LabOperation
from app.models.person import Person
from app.services import lab_console_activity as lca
from app.services import lab_jobs


@pytest.fixture(autouse=True)
def _fresh_throttle():
    lca.reset_throttle()
    yield
    lca.reset_throttle()


def _instance(admin_session, tenant, *, name, last_active=None):
    c = Course(tenant_id=tenant.id, slug=f"c-{name}", title="F", discipline="networking",
               source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()
    act = Activity(tenant_id=tenant.id, course_id=c.id, chapter_number=1, type="lab",
                   title="L", pass_threshold=0.6)
    p = Person(tenant_id=tenant.id, email=f"{name}@example.com", first_name="T", last_name="U")
    admin_session.add_all([act, p])
    admin_session.flush()
    inst = LabInstance(tenant_id=tenant.id, activity_id=act.id, person_id=p.id,
                       instance_name=f"dal-{name}", seed={}, status="active", consoles={},
                       last_active_at=last_active)
    admin_session.add(inst)
    admin_session.commit()
    return inst


def _put_seen(admin_session, inst, tenant, ts):
    """Backdate a heartbeat. The stamp trigger overwrites every client value, so
    fixtures bypass it with replica mode (superuser only), then restore it."""
    admin_session.execute(text("SET LOCAL session_replication_role = replica"))
    admin_session.execute(
        text("INSERT INTO lab_console_activity (instance_id, tenant_id, last_seen_at) "
             "VALUES (:i, :t, :ts) ON CONFLICT (instance_id) DO UPDATE SET last_seen_at = :ts"),
        {"i": inst.id, "t": tenant.id, "ts": ts},
    )
    admin_session.commit()  # SET LOCAL ends with the transaction


def _as_tenant(db, tenant):
    db.execute(text("SELECT set_config('app.current_tenant', :t, true)"), {"t": str(tenant.id)})


def _seen(admin_session, inst):
    admin_session.expire_all()
    row = admin_session.get(LabConsoleActivity, inst.id)
    return row.last_seen_at if row else None


def test_record_writes_once_then_is_rate_limited(admin_session, app_user_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="rl1")
    db = app_user_session
    _as_tenant(db, tenant_a)
    assert lca.record(db, tenant_id=tenant_a.id, instance_id=inst.id) is True
    db.commit()
    first = _seen(admin_session, inst)
    assert first is not None

    # In-process gate: no statement at all within the interval.
    _as_tenant(db, tenant_a)
    assert lca.record(db, tenant_id=tenant_a.id, instance_id=inst.id) is False
    assert _seen(admin_session, inst) == first


def test_sql_guard_skips_a_fresh_row_even_when_the_process_gate_is_open(
    admin_session, app_user_session, tenant_a
):
    """A second web worker (own throttle) still cannot rewrite a fresh row."""
    inst = _instance(admin_session, tenant_a, name="rl2")
    db = app_user_session
    _as_tenant(db, tenant_a)
    lca.record(db, tenant_id=tenant_a.id, instance_id=inst.id)
    db.commit()
    first = _seen(admin_session, inst)

    lca.reset_throttle()  # simulate another process
    _as_tenant(db, tenant_a)
    assert lca.record(db, tenant_id=tenant_a.id, instance_id=inst.id) is True  # issued...
    db.commit()
    assert _seen(admin_session, inst) == first  # ...but the guard did not rewrite


def test_stale_row_is_refreshed(admin_session, app_user_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="rl3")
    old = datetime.now(UTC) - timedelta(minutes=10)
    _put_seen(admin_session, inst, tenant_a, old)
    db = app_user_session
    _as_tenant(db, tenant_a)
    lca.record(db, tenant_id=tenant_a.id, instance_id=inst.id)
    db.commit()
    assert _seen(admin_session, inst) > old + timedelta(minutes=9)


def test_in_process_throttle_is_bounded():
    from uuid import uuid4

    for _ in range(lca._MAX_TRACKED + 50):
        lca.try_acquire(uuid4())
    assert len(lca._last_attempt) <= lca._MAX_TRACKED


def test_tenant_rls_blocks_a_heartbeat_for_another_tenants_instance(
    admin_session, app_user_session, tenant_a, tenant_b
):
    inst_b = _instance(admin_session, tenant_b, name="rls1")
    db = app_user_session
    _as_tenant(db, tenant_a)  # session is tenant A, instance is tenant B's
    with pytest.raises(DBAPIError):
        lca.record(db, tenant_id=tenant_b.id, instance_id=inst_b.id)
        db.flush()
    db.rollback()
    assert _seen(admin_session, inst_b) is None


def test_app_user_privileges_are_column_scoped_and_lab_instances_stays_read_only(app_user_session):
    db = app_user_session

    def has(priv, table="lab_console_activity", column=None):
        if column:
            return db.scalar(text("SELECT has_column_privilege('app_user', :t, :c, :p)"),
                             {"t": table, "c": column, "p": priv})
        return db.scalar(text("SELECT has_table_privilege('app_user', :t, :p)"), {"t": table, "p": priv})

    assert has("SELECT")
    assert not has("DELETE") and not has("TRUNCATE")
    assert has("UPDATE", column="last_seen_at")
    for column in ("instance_id", "tenant_id"):
        assert not has("UPDATE", column=column)
    # The invariant this design preserves: the web tier cannot write instances.
    assert not has("UPDATE", table="lab_instances")
    assert not has("UPDATE", table="lab_instances", column="last_active_at")
    assert not has("UPDATE", table="lab_instances", column="status")


def test_other_roles_have_no_access(app_user_session):
    db = app_user_session
    for role in ("platform_api", "academy_lab_worker"):
        for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            assert not db.scalar(
                text("SELECT has_table_privilege(:r, 'lab_console_activity', :p)"), {"r": role, "p": priv}
            ), (role, priv)


def test_deleting_an_instance_cascades(admin_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="cas1")
    _put_seen(admin_session, inst, tenant_a, datetime.now(UTC))
    admin_session.delete(inst)
    admin_session.commit()
    assert admin_session.get(LabConsoleActivity, inst.id) is None


# --- idle reaper ---------------------------------------------------------


def _ops(admin_session, inst):
    return admin_session.query(LabOperation).filter_by(instance_id=inst.id).count()


def test_reaper_still_reaps_an_idle_lab_without_heartbeat(admin_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="rp1",
                     last_active=datetime.now(UTC) - timedelta(minutes=999))
    assert lab_jobs.request_idle_reaps(admin_session) == 1
    assert _ops(admin_session, inst) == 1


def test_recent_console_heartbeat_keeps_the_lab_alive(admin_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="rp2",
                     last_active=datetime.now(UTC) - timedelta(minutes=999))
    _put_seen(admin_session, inst, tenant_a, datetime.now(UTC) - timedelta(minutes=5))
    assert lab_jobs.request_idle_reaps(admin_session) == 0
    assert _ops(admin_session, inst) == 0


def test_stale_heartbeat_does_not_save_an_idle_lab(admin_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="rp3",
                     last_active=datetime.now(UTC) - timedelta(minutes=999))
    _put_seen(admin_session, inst, tenant_a, datetime.now(UTC) - timedelta(minutes=500))
    assert lab_jobs.request_idle_reaps(admin_session) == 1


def test_recent_lifecycle_activity_still_counts_with_an_old_heartbeat(admin_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="rp4",
                     last_active=datetime.now(UTC) - timedelta(minutes=2))
    _put_seen(admin_session, inst, tenant_a, datetime.now(UTC) - timedelta(minutes=500))
    assert lab_jobs.request_idle_reaps(admin_session) == 0


# --- the database clock is the only clock ---------------------------------


def test_client_supplied_future_timestamp_is_overwritten_on_insert(admin_session, app_user_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="trg1")
    db = app_user_session
    _as_tenant(db, tenant_a)
    future = datetime.now(UTC) + timedelta(days=3650)
    db.execute(
        text("INSERT INTO lab_console_activity (instance_id, tenant_id, last_seen_at) VALUES (:i, :t, :ts)"),
        {"i": inst.id, "t": tenant_a.id, "ts": future},
    )
    db.commit()
    seen = _seen(admin_session, inst)
    assert abs((seen - datetime.now(UTC)).total_seconds()) < 60


def test_client_supplied_future_timestamp_is_overwritten_on_update(admin_session, app_user_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="trg2")
    old = datetime.now(UTC) - timedelta(hours=3)
    _put_seen(admin_session, inst, tenant_a, old)
    db = app_user_session
    _as_tenant(db, tenant_a)
    db.execute(
        text("UPDATE lab_console_activity SET last_seen_at = :ts WHERE instance_id = :i"),
        {"i": inst.id, "ts": datetime.now(UTC) + timedelta(days=3650)},
    )
    db.commit()
    seen = _seen(admin_session, inst)
    assert abs((seen - datetime.now(UTC)).total_seconds()) < 60


def test_a_future_value_cannot_keep_a_lab_from_being_reaped(admin_session, app_user_session, tenant_a):
    inst = _instance(admin_session, tenant_a, name="trg3",
                     last_active=datetime.now(UTC) - timedelta(minutes=999))
    db = app_user_session
    _as_tenant(db, tenant_a)
    db.execute(
        text("INSERT INTO lab_console_activity (instance_id, tenant_id, last_seen_at) VALUES (:i, :t, :ts)"),
        {"i": inst.id, "t": tenant_a.id, "ts": datetime.now(UTC) + timedelta(days=3650)},
    )
    db.commit()
    # The stamp is the database clock, not the future value: the lab is alive now...
    assert lab_jobs.request_idle_reaps(admin_session) == 0
    # ...and goes idle again once real time passes (simulated by backdating).
    _put_seen(admin_session, inst, tenant_a, datetime.now(UTC) - timedelta(minutes=999))
    assert lab_jobs.request_idle_reaps(admin_session) == 1


def test_exact_column_grants_and_forced_rls(app_user_session):
    db = app_user_session
    cols = [r[0] for r in db.execute(text(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'lab_console_activity'"))]
    assert set(cols) == {"instance_id", "tenant_id", "last_seen_at"}

    def col(priv, c):
        return db.scalar(text("SELECT has_column_privilege('app_user', 'lab_console_activity', :c, :p)"),
                         {"c": c, "p": priv})

    # INSERT is column-scoped to exactly the three columns; UPDATE to one.
    assert {c for c in cols if col("INSERT", c)} == set(cols)
    assert {c for c in cols if col("UPDATE", c)} == {"last_seen_at"}
    # No table-wide INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER beyond the above.
    acl = db.scalar(text("SELECT relacl::text FROM pg_class WHERE relname = 'lab_console_activity'"))
    app_entry = [e for e in (acl or "").strip("{}").split(",") if e.startswith("app_user=")]
    assert app_entry == ["app_user=r/app_admin"] or app_entry == ["app_user=r/postgres"] or all(
        set(e.split("=")[1].split("/")[0]) <= {"r"} for e in app_entry
    ), acl
    flags = db.execute(text(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'lab_console_activity'"
    )).one()
    assert tuple(flags) == (True, True)
    policy = db.scalar(text("SELECT count(*) FROM pg_policies WHERE tablename = 'lab_console_activity'"))
    assert policy == 1
