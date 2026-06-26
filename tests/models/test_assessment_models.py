from app.models.course import Course
from app.models.assessment import QuestionBank, Question, Activity, Submission, Score


def test_assessment_chain(admin_session, tenant_a):
    c = Course(tenant_id=tenant_a.id, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    admin_session.add(c); admin_session.flush()
    bank = QuestionBank(tenant_id=tenant_a.id, course_id=c.id, chapter_number=3, kind="chapter", version=1)
    admin_session.add(bank); admin_session.flush()
    q = Question(tenant_id=tenant_a.id, bank_id=bank.id, ext_id="q1", stem="?", type="single",
                 options=["A", "B"], correct=["A"], rubric_category="recall", explanation="", weight=1)
    admin_session.add(q); admin_session.flush()
    act = Activity(tenant_id=tenant_a.id, course_id=c.id, chapter_number=3, type="mcq_test",
                   bank_id=bank.id, title="Ch3 test", pass_threshold=0.6)
    admin_session.add(act); admin_session.flush()
    sub = Submission(tenant_id=tenant_a.id, activity_id=act.id, person_id=c.id,  # any uuid for the row
                     answers={"q1": ["A"]}, attempt_no=1)
    admin_session.add(sub); admin_session.flush()
    sc = Score(tenant_id=tenant_a.id, submission_id=sub.id, score=1.0, max_score=1.0,
               fraction=1.0, passed=True, per_item=[{"id": "q1", "correct": True}], source="auto")
    admin_session.add(sc); admin_session.flush()
    assert sc.passed is True
    admin_session.rollback()
