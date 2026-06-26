import uuid
from sqlalchemy import text
from app.models.course import Course
from app.models.assessment import QuestionBank


def test_question_bank_invisible_across_tenants(admin_session, tenant_a, tenant_b):
    # Create a Course in tenant_a (required FK for QuestionBank)
    c = Course(tenant_id=tenant_a.id, slug=f"foundation-{uuid.uuid4().hex[:8]}", title="F",
               discipline="networking", source_ref="x", version=1)
    admin_session.add(c)
    admin_session.flush()

    # Create a QuestionBank in tenant_a
    bank = QuestionBank(tenant_id=tenant_a.id, course_id=c.id, chapter_number=1,
                        kind="chapter", version=1)
    admin_session.add(bank)
    admin_session.commit()

    # Simulate an app_user session scoped to tenant_b
    # SET command does not accept bound parameters in PostgreSQL — safe to interpolate UUID
    admin_session.execute(text(f"SET app.current_tenant = '{tenant_b.id}'"))
    admin_session.execute(text("SET ROLE app_user;"))
    rows = admin_session.execute(text("SELECT count(*) FROM question_banks")).scalar()
    admin_session.execute(text("RESET ROLE"))
    admin_session.execute(text("RESET app.current_tenant"))
    assert rows == 0

    # Cleanup
    admin_session.query(QuestionBank).filter(QuestionBank.id == bank.id).delete()
    admin_session.query(Course).filter(Course.id == c.id).delete()
    admin_session.commit()
