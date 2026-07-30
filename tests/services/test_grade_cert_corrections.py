"""Review corrections R2-A: below-passing graded-only trigger + volume gate,
and certificate auto-issue on completion."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.assessment import Activity, Score, Submission
from app.models.certificate import Certificate
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services import success_queue
from app.services.certificates import issue_certificate
from app.services.completion import recompute_completion
from app.services.gradebook import attempted_grade


def _course_with_activities(admin_session, tenant, slug, *, n, weight=1):
    person = Person(tenant_id=tenant.id, email=f"{slug}@a.edu", first_name="G", last_name="C")
    admin_session.add(person)
    course = Course(tenant_id=tenant.id, slug=slug, title=slug.title(),
                    discipline="fiber", source_ref="t@1", status="published")
    admin_session.add(course)
    cohort = Cohort(tenant_id=tenant.id, name=f"C {slug}", discipline="fiber", status="active")
    admin_session.add(cohort)
    admin_session.flush()
    admin_session.add(Enrollment(tenant_id=tenant.id, cohort_id=cohort.id, person_id=person.id,
                                 role_in_cohort="student", status="active"))
    admin_session.add(CourseOffering(tenant_id=tenant.id, cohort_id=cohort.id,
                                     course_id=course.id, status="active"))
    acts = []
    for i in range(n):
        a = Activity(tenant_id=tenant.id, course_id=course.id, chapter_number=i + 1,
                     type="mcq_test", title=f"A{i}", pass_threshold=0.6, weight=weight)
        admin_session.add(a)
        acts.append(a)
    admin_session.flush()
    return person, course, acts


def _score(admin_session, tenant, person, act, fraction):
    sub = Submission(tenant_id=tenant.id, activity_id=act.id, person_id=person.id, answers={})
    admin_session.add(sub)
    admin_session.flush()
    admin_session.add(Score(tenant_id=tenant.id, submission_id=sub.id, score=int(fraction * 10),
                            max_score=10, fraction=fraction, passed=fraction >= 0.6,
                            per_item=[], source="auto"))
    admin_session.flush()


def test_attempted_grade_is_graded_only(admin_session, tenant_a):
    person, course, acts = _course_with_activities(admin_session, tenant_a, "att-grade", n=4)
    _score(admin_session, tenant_a, person, acts[0], 0.4)  # graded
    _score(admin_session, tenant_a, person, acts[1], 0.6)  # graded
    admin_session.commit()
    g = attempted_grade(admin_session, tenant_id=tenant_a.id, person_id=person.id, course_id=course.id)
    assert g["graded_count"] == 2
    assert g["graded_weight_fraction"] == 0.5          # 2 of 4 equal-weight activities
    assert g["pct"] == 50                               # (0.4 + 0.6)/2 — course_grade would say 25


def test_below_passing_fires_with_volume_gate(admin_session, tenant_a):
    person, course, acts = _course_with_activities(admin_session, tenant_a, "bp-fire", n=5)
    _score(admin_session, tenant_a, person, acts[0], 0.2)
    _score(admin_session, tenant_a, person, acts[1], 0.3)   # 2 graded, 40% weight, avg 25% < 60
    admin_session.commit()
    hit = success_queue._rule_below_passing(
        admin_session, tenant_id=tenant_a.id, person_id=person.id,
        course_ids=[course.id], min_grade_pct=60,
    )
    assert hit is not None
    facts = hit[0]
    assert facts["grade_pct"] == 25 and facts["graded_count"] == 2 and facts["graded_weight_pct"] == 40


def test_below_passing_silent_below_volume_gate(admin_session, tenant_a):
    # One graded activity: below the 2-graded minimum -> no false positive.
    person, course, acts = _course_with_activities(admin_session, tenant_a, "bp-one", n=5)
    _score(admin_session, tenant_a, person, acts[0], 0.1)
    admin_session.commit()
    assert success_queue._rule_below_passing(
        admin_session, tenant_id=tenant_a.id, person_id=person.id,
        course_ids=[course.id], min_grade_pct=60,
    ) is None

    # Two graded but < 20% of course weight (2 of 20) -> still silent.
    p2, c2, a2 = _course_with_activities(admin_session, tenant_a, "bp-weight", n=20)
    _score(admin_session, tenant_a, p2, a2[0], 0.1)
    _score(admin_session, tenant_a, p2, a2[1], 0.1)
    admin_session.commit()
    assert success_queue._rule_below_passing(
        admin_session, tenant_id=tenant_a.id, person_id=p2.id,
        course_ids=[c2.id], min_grade_pct=60,
    ) is None


def test_certificate_auto_issued_on_completion(admin_session, tenant_a):
    person, course, acts = _course_with_activities(admin_session, tenant_a, "cert-auto", n=2)
    for a in acts:
        _score(admin_session, tenant_a, person, a, 1.0)
    # Learner has opted out of result emails: issuance must still happen.
    person.prefs = {"email_results": False}
    admin_session.flush()
    rec = recompute_completion(admin_session, tenant_id=tenant_a.id, person_id=person.id, course_id=course.id)
    admin_session.commit()
    assert rec.status == "completed"
    cert = admin_session.query(Certificate).filter_by(
        tenant_id=tenant_a.id, person_id=person.id, course_id=course.id).one()
    assert cert.serial and cert.issued_at is not None
    # Idempotent: a second issue returns the same record.
    again = issue_certificate(admin_session, tenant_id=tenant_a.id, person_id=person.id, course_id=course.id)
    assert again.id == cert.id


def test_certificate_blocked_only_after_grace(admin_session, tenant_a):
    person, course, acts = _course_with_activities(admin_session, tenant_a, "cert-block", n=1)
    _score(admin_session, tenant_a, person, acts[0], 1.0)
    rec = recompute_completion(admin_session, tenant_id=tenant_a.id, person_id=person.id, course_id=course.id)
    admin_session.commit()
    # Auto-issued -> no blocked entry regardless of grace.
    assert success_queue._rule_certificate_blocked(
        admin_session, tenant_id=tenant_a.id, person_id=person.id,
        now=datetime.now(UTC) + timedelta(hours=24), grace_hours=6,
    ) is None
    # Simulate genuine issuance failure: remove the cert, backdate completion.
    admin_session.query(Certificate).filter_by(
        tenant_id=tenant_a.id, person_id=person.id, course_id=course.id).delete()
    rec.completed_at = datetime.now(UTC) - timedelta(hours=10)
    admin_session.flush()
    within = success_queue._rule_certificate_blocked(
        admin_session, tenant_id=tenant_a.id, person_id=person.id,
        now=datetime.now(UTC), grace_hours=48,   # still inside grace -> silent
    )
    assert within is None
    past = success_queue._rule_certificate_blocked(
        admin_session, tenant_id=tenant_a.id, person_id=person.id,
        now=datetime.now(UTC), grace_hours=6,    # past grace -> fires
    )
    assert past is not None and past[0]["missing"] == "certificate"
