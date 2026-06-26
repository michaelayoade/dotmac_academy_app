from app.models.course import Course, Chapter


def test_course_and_chapter(admin_session, tenant_a):
    c = Course(tenant_id=tenant_a.id, slug="foundation", title="Foundation",
               discipline="networking", source_ref="foundation@0.1.0", version=1)
    admin_session.add(c); admin_session.flush()
    ch = Chapter(tenant_id=tenant_a.id, course_id=c.id, number=1, title="Welcome",
                 part="I", body_html="<p>hi</p>", source_hash="abc", order_index=1)
    admin_session.add(ch); admin_session.flush()
    assert ch.course_id == c.id
    admin_session.rollback()
