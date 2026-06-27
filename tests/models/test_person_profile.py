from app.models.person import Person


def test_person_profile_round_trip(admin_session, tenant_a):
    p = Person(tenant_id=tenant_a.id, email="prof@example.com", first_name="Pro",
               last_name="File", prefs={"email_results": False},
               avatar_path="/static/avatars/x.png")
    admin_session.add(p); admin_session.flush()
    admin_session.refresh(p)
    assert p.avatar_path == "/static/avatars/x.png"
    assert p.prefs == {"email_results": False}
    admin_session.rollback()


def test_person_prefs_defaults_to_empty(admin_session, tenant_a):
    p = Person(tenant_id=tenant_a.id, email="noprefs@example.com",
               first_name="No", last_name="Prefs")
    admin_session.add(p); admin_session.flush()
    admin_session.refresh(p)
    assert p.prefs == {}
    assert p.avatar_path is None
    admin_session.rollback()
