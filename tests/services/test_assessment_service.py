# tests/services/test_assessment_service.py
import pytest
from app.models.course import Course
from app.models.person import Person
from app.models.assessment import QuestionBank, Question, Activity, Submission
from app.services import email as email_mod
from app.services.assessment import submit_activity, best_scores_for, override_score
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


def test_submit_activity_auto_on_pass_notifies_once(admin_session, tenant_a, monkeypatch):
    """First passing submit emails the student exactly once; a later pass does not."""
    calls = []
    monkeypatch.setattr(email_mod, "send_email",
                        lambda to, subject, html, text_body=None: calls.append(to) or True)
    c, act = _seed(admin_session, tenant_a.id)
    p = Person(tenant_id=tenant_a.id, email="pass@stu.edu", first_name="Pa", last_name="Ss")
    admin_session.add(p)
    admin_session.flush()

    # Fail first → no email.
    submit_activity(admin_session, tenant_id=tenant_a.id, person_id=p.id, activity=act, answers={"q1": ["B"]})
    assert calls == []
    # First pass → one email.
    submit_activity(admin_session, tenant_id=tenant_a.id, person_id=p.id, activity=act, answers={"q1": ["A"]})
    assert calls == ["pass@stu.edu"]
    # Second pass → still just one.
    submit_activity(admin_session, tenant_id=tenant_a.id, person_id=p.id, activity=act, answers={"q1": ["A"]})
    assert calls == ["pass@stu.edu"]
    admin_session.rollback()


def test_best_is_highest_not_latest(admin_session, tenant_a):
    """best_scores_for must return the highest-fraction score, not the most recent."""
    person_id = uuid4()
    c, act = _seed(admin_session, tenant_a.id)
    # First attempt: correct answer → fraction 1.0
    submit_activity(admin_session, tenant_id=tenant_a.id, person_id=person_id, activity=act, answers={"q1": ["A"]})
    # Second attempt: wrong answer → fraction 0.0  (latest)
    submit_activity(admin_session, tenant_id=tenant_a.id, person_id=person_id, activity=act, answers={"q1": ["B"]})
    admin_session.flush()
    best = best_scores_for(admin_session, tenant_id=tenant_a.id, person_id=person_id, course_id=c.id)
    assert best[act.id].fraction == 1.0, "best_scores_for returned latest (0.0), not highest (1.0)"
    admin_session.rollback()


def test_override_score_threshold_and_tenant_validation(admin_session, tenant_a):
    """override_score computes passed vs real threshold and rejects foreign submission_ids."""
    person_id = uuid4()
    c, act = _seed(admin_session, tenant_a.id)  # act has pass_threshold=0.6
    # Create a real submission via submit_activity
    submitted = submit_activity(admin_session, tenant_id=tenant_a.id, person_id=person_id,
                                activity=act, answers={"q1": ["B"]})
    # Fetch the submission to get its id
    from sqlalchemy import select as sa_select
    from app.models.assessment import Submission as Sub
    sub = admin_session.scalars(
        sa_select(Sub).where(Sub.tenant_id == tenant_a.id).where(Sub.activity_id == act.id)
    ).first()
    # score_value=3, max_score=10 → frac=0.3 < 0.6 threshold → passed must be False
    result = override_score(admin_session, tenant_id=tenant_a.id, submission_id=sub.id,
                            score_value=3, max_score=10, reason="manual review")
    assert result.passed is False, f"expected passed=False, got {result.passed}"
    assert result.source == "override"
    # Tenant validation: random uuid should raise ValueError
    with pytest.raises(ValueError):
        override_score(admin_session, tenant_id=tenant_a.id, submission_id=uuid4(),
                       score_value=5, max_score=10, reason="should fail")
    admin_session.rollback()
