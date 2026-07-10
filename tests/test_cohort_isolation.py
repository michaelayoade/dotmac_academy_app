import uuid

from sqlalchemy import text

from app.models.cohort import Cohort


def test_cohort_invisible_across_tenants(admin_session, tenant_a, tenant_b):
    co = Cohort(tenant_id=tenant_a.id, name=f"Test Cohort {uuid.uuid4().hex[:8]}",
                discipline="networking", status="active")
    admin_session.add(co); admin_session.commit()
    # Simulate an app_user session scoped to tenant_b
    # SET command does not accept bound parameters in PostgreSQL — safe to interpolate UUID
    admin_session.execute(text(f"SET app.current_tenant = '{tenant_b.id}'"))
    admin_session.execute(text("SET ROLE app_user;"))
    rows = admin_session.execute(text("SELECT count(*) FROM cohorts")).scalar()
    admin_session.execute(text("RESET ROLE"))
    admin_session.execute(text("RESET app.current_tenant"))
    assert rows == 0
    admin_session.query(Cohort).filter(Cohort.id == co.id).delete(); admin_session.commit()
