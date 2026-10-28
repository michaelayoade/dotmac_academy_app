"""Profile fields round-trip on the canonical account profile.

The legacy ``Person.prefs``/``avatar_path`` columns are owned composed-side by
``AcademyAccountProfile`` (keyed by the Party id), so the round-trip is
asserted there.
"""

from sqlalchemy import select

from app.models.identity_extensions import AcademyAccountProfile
from tests.conftest import make_person_party


def _profile(admin_session, party_id):
    return admin_session.scalars(
        select(AcademyAccountProfile).where(AcademyAccountProfile.party_id == party_id)
    ).one()


def test_person_profile_round_trip(admin_session, tenant_a):
    p = make_person_party(
        admin_session,
        tenant_id=tenant_a.id,
        email="prof@example.com",
        first_name="Pro",
        last_name="File",
        prefs={"email_results": False},
        avatar_path="/static/avatars/x.png",
    )
    admin_session.flush()
    profile = _profile(admin_session, p.id)
    admin_session.refresh(profile)
    assert profile.avatar_path == "/static/avatars/x.png"
    assert profile.prefs == {"email_results": False}
    admin_session.rollback()


def test_person_prefs_defaults_to_empty(admin_session, tenant_a):
    p = make_person_party(
        admin_session,
        tenant_id=tenant_a.id,
        email="noprefs@example.com",
        first_name="No",
        last_name="Prefs",
    )
    admin_session.flush()
    profile = _profile(admin_session, p.id)
    admin_session.refresh(profile)
    assert profile.prefs == {}
    assert profile.avatar_path is None
    admin_session.rollback()
