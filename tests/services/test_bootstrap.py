"""TDD test for the tenant bootstrap service."""

from app.services.bootstrap import bootstrap_tenant, ensure_roles
from app.models.rbac import Role, PersonRole
from app.models.person import Person


def test_bootstrap_creates_tenant_roles_and_admin(admin_session):
    t = bootstrap_tenant(admin_session, slug="acme", name="Acme U",
                          admin_email="dean@acme.edu", admin_password="supersecret")
    admin_session.commit()
    slugs = {r.slug for r in admin_session.query(Role).filter(Role.tenant_id == t.id)}
    assert slugs == {"student", "instructor", "admin"}
    admin = admin_session.query(Person).filter(Person.tenant_id == t.id).one()
    grants = admin_session.query(PersonRole).filter(PersonRole.tenant_id == t.id,
                                                    PersonRole.person_id == admin.id).all()
    assert len(grants) == 1
    # Cleanup
    admin_session.query(PersonRole).filter(PersonRole.tenant_id == t.id).delete()
    admin_session.query(Person).filter(Person.tenant_id == t.id).delete()
    admin_session.query(Role).filter(Role.tenant_id == t.id).delete()
    from app.models.tenant import Tenant
    admin_session.query(Tenant).filter(Tenant.id == t.id).delete()
    admin_session.commit()
