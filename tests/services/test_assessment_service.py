# tests/services/test_assessment_service.py
from app.models.course import Course
from app.models.assessment import QuestionBank, Question, Activity
from app.services.assessment import submit_activity, best_scores_for
from uuid import uuid4

def _seed(db, tid):
    c = Course(tenant_id=tid, slug="foundation", title="F", discipline="networking", source_ref="x", version=1)
    db.add(c); db.flush()
    bank = QuestionBank(tenant_id=tid, course_id=c.id, chapter_number=3, kind="chapter", version=1)
    db.add(bank); db.flush()
    db.add(Question(tenant_id=tid, bank_id=bank.id, ext_id="q1", stem="?", type="single",
                    options=["A", "B"], correct=["A"], rubric_category="recall", explanation="", weight=1))
    act = Activity(tenant_id=tid, course_id=c.id, chapter_number=3, type="mcq_test",
                   bank_id=bank.id, title="Ch3", pass_threshold=0.6)
    db.add(act); db.flush()
    return c, act

def test_submit_and_best(admin_session, tenant_a):
    person_id = uuid4()
    c, act = _seed(admin_session, tenant_a.id)
    s1 = submit_activity(admin_session, tenant_id=tenant_a.id, person_id=person_id, activity=act, answers={"q1": ["B"]})
    s2 = submit_activity(admin_session, tenant_id=tenant_a.id, person_id=person_id, activity=act, answers={"q1": ["A"]})
    admin_session.flush()
    assert s1.passed is False and s2.passed is True
    best = best_scores_for(admin_session, tenant_id=tenant_a.id, person_id=person_id, course_id=c.id)
    assert best[act.id].fraction == 1.0
    admin_session.rollback()
