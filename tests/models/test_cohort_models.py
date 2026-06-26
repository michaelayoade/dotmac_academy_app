from app.models.cohort import Cohort, Enrollment
from app.models.person import Person


def test_enroll(admin_session, tenant_a):
    co = Cohort(tenant_id=tenant_a.id, name="Abuja 2026", discipline="networking", status="active")
    admin_session.add(co); admin_session.flush()
    p = Person(tenant_id=tenant_a.id, email="s2@a.edu", first_name="A", last_name="B")
    admin_session.add(p); admin_session.flush()
    e = Enrollment(tenant_id=tenant_a.id, cohort_id=co.id, person_id=p.id,
                   role_in_cohort="student", status="active")
    admin_session.add(e); admin_session.flush()
    assert e.cohort_id == co.id
    admin_session.rollback()
