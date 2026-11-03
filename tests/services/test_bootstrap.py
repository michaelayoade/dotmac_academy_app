"""Tenant bootstrap creates the three standard roles and grants the admin role to the owner.

Role admission guard: the web facets admit student/instructor/admin only, so a bootstrap
that drifts from exactly these three roles, or grants the owner anything but admin, must fail here.
The owner-credential shape (Party/PartyPerson/profile/credential extension) is asserted by
tests/services/test_bootstrap_identity.py, which owns the offline runtime fixture used below.
"""

from __future__ import annotations

from uuid import uuid4

from dotmac_kernel.models import Party, PartyRoleGrant, Role
from sqlalchemy import select, text

from app.services.bootstrap import bootstrap_tenant
from tests.services.test_bootstrap_identity import offline_runtime  # noqa: F401  (fixture)


def test_bootstrap_creates_the_three_standard_roles_and_one_admin_grant(offline_runtime, admin_session):  # noqa: F811
    slug = "bootstrap-roles-" + uuid4().hex
    tid = None
    try:
        with offline_runtime.platform_session() as db:
            result = bootstrap_tenant(
                db, slug=slug, name="Roles Tenant", admin_email=slug + "@example.test",
                admin_password="hosted-bootstrap-secret-923!",
            )
            tid, pid = result.id, result.owner_party_id
        with offline_runtime.platform_session() as db:
            offline_runtime.set_tenant(db, tid, transaction_local=True)
            roles = db.scalars(select(Role).where(Role.tenant_id == tid)).all()
            assert {r.slug for r in roles} == {"student", "instructor", "admin"}
            assert len(roles) == 3, "no duplicate role rows"
            grants = db.scalars(select(PartyRoleGrant).where(PartyRoleGrant.tenant_id == tid)).all()
            assert len(grants) == 1, "the owner receives exactly one grant"
            assert grants[0].party_id == pid
            assert db.get(Role, grants[0].role_id).slug == "admin"
            assert db.get(Party, pid).tenant_id == tid
    finally:
        # bootstrap_tenant commits through the platform runtime; remove the tenant (cascades) so it
        # does not leak into tests that count tenant rows.
        admin_session.rollback()
        if tid is not None:
            admin_session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(tid)})
        else:
            admin_session.execute(text("DELETE FROM tenants WHERE slug = :s"), {"s": slug})
        admin_session.commit()
