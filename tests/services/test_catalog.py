# tests/services/test_catalog.py
"""Unit tests for app/services/catalog.py."""

from __future__ import annotations

from app.models.assessment import Activity, Question, QuestionBank
from app.models.cohort import Cohort, Enrollment
from app.models.course import Chapter, Course
from app.models.offering import CourseOffering
from app.models.person import Person
from app.models.prerequisite import CoursePrerequisite
from app.services.assessment import submit_activity
from app.services.catalog import (
    all_courses,
    course_completion,
    course_structure,
    my_courses,
)


def _seed_course(db, tid, slug, title="Test Course"):
    c = Course(
        tenant_id=tid, slug=slug, title=title, discipline="networking",
        source_ref="x", version=1, status="published",
    )
    db.add(c)
    db.flush()
    return c


def _seed_chapter(db, tid, course_id, number, title="Ch", part="I", order_index=None):
    ch = Chapter(
        tenant_id=tid, course_id=course_id, number=number, title=title,
        part=part, body_html="<p>x</p>", source_hash="h",
        order_index=order_index if order_index is not None else number,
    )
    db.add(ch)
    db.flush()
    return ch


def _seed_activity(db, tid, course_id, chapter_number, title="Act"):
    bank = QuestionBank(tenant_id=tid, course_id=course_id, chapter_number=chapter_number, kind="chapter", version=1)
    db.add(bank)
    db.flush()
    db.add(Question(tenant_id=tid, bank_id=bank.id, ext_id="q1", stem="Q?", type="single",
                    options=["A", "B"], correct=["A"], rubric_category="recall", explanation="", weight=1))
    act = Activity(tenant_id=tid, course_id=course_id, chapter_number=chapter_number,
                   type="mcq_test", bank_id=bank.id, title=title, pass_threshold=0.6)
    db.add(act)
    db.flush()
    return act


def _enroll(db, tid, person_id, course_id):
    coh = Cohort(tenant_id=tid, name="Coh", discipline="networking", status="active")
    db.add(coh)
    db.flush()
    db.add(Enrollment(tenant_id=tid, cohort_id=coh.id, person_id=person_id,
                      role_in_cohort="student", status="active"))
    db.add(CourseOffering(tenant_id=tid, cohort_id=coh.id, course_id=course_id, status="active"))
    db.flush()
    return coh


def test_my_courses_returns_only_accessible(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_stu@a.edu", first_name="Cat", last_name="Stu")
    admin_session.add(person)
    admin_session.flush()

    c1 = _seed_course(admin_session, tid, "cat-c1", "Course One")
    _seed_course(admin_session, tid, "cat-c2", "Course Two")
    _enroll(admin_session, tid, person.id, c1.id)
    # cat-c2 NOT enrolled

    result = my_courses(admin_session, tenant_id=tid, person_id=person.id)
    titles = [c.title for c in result]
    admin_session.rollback()

    assert "Course One" in titles
    assert "Course Two" not in titles


def test_my_courses_empty_when_no_enrollment(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_noroll@a.edu", first_name="No", last_name="Roll")
    admin_session.add(person)
    _seed_course(admin_session, tid, "cat-noroll-c", "No Roll Course")
    admin_session.flush()

    result = my_courses(admin_session, tenant_id=tid, person_id=person.id)
    n = len(result)
    admin_session.rollback()
    assert n == 0


def test_all_courses_returns_all_tenant_courses(admin_session, tenant_a):
    tid = tenant_a.id
    c1 = _seed_course(admin_session, tid, "cat-all1", "All One")
    c2 = _seed_course(admin_session, tid, "cat-all2", "All Two")
    admin_session.flush()

    result = all_courses(admin_session, tenant_id=tid)
    ids = {c.id for c in result}
    c1_id, c2_id = c1.id, c2.id
    admin_session.rollback()

    assert c1_id in ids
    assert c2_id in ids


def test_all_courses_ordered_by_title(admin_session, tenant_a):
    tid = tenant_a.id
    _seed_course(admin_session, tid, "cat-ord-z", "Zebra Course")
    _seed_course(admin_session, tid, "cat-ord-a", "Apple Course")
    admin_session.flush()

    result = all_courses(admin_session, tenant_id=tid)
    # Collect titles while session is still active
    titles = [c.title for c in result]
    admin_session.rollback()

    apple_idx = next(i for i, t in enumerate(titles) if t == "Apple Course")
    zebra_idx = next(i for i, t in enumerate(titles) if t == "Zebra Course")
    assert apple_idx < zebra_idx


def test_course_completion_no_activities(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_comp0@a.edu", first_name="C", last_name="O")
    admin_session.add(person)
    c = _seed_course(admin_session, tid, "cat-comp0", "Empty Course")
    admin_session.flush()

    pct = course_completion(admin_session, tenant_id=tid, person_id=person.id, course_id=c.id)
    admin_session.rollback()
    assert pct == 0


def test_course_completion_partial(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_comp_p@a.edu", first_name="P", last_name="C")
    admin_session.add(person)
    admin_session.flush()
    c = _seed_course(admin_session, tid, "cat-comp-p", "Partial Course")
    _seed_chapter(admin_session, tid, c.id, 1)
    _seed_chapter(admin_session, tid, c.id, 2)
    act1 = _seed_activity(admin_session, tid, c.id, 1, "Act1")
    act2 = _seed_activity(admin_session, tid, c.id, 2, "Act2")
    admin_session.flush()

    # Pass act1 only
    submit_activity(admin_session, tenant_id=tid, person_id=person.id, activity=act1, answers={"q1": ["A"]})
    admin_session.flush()
    # Fail act2
    submit_activity(admin_session, tenant_id=tid, person_id=person.id, activity=act2, answers={"q1": ["B"]})
    admin_session.flush()

    pct = course_completion(admin_session, tenant_id=tid, person_id=person.id, course_id=c.id)
    admin_session.rollback()
    assert pct == 50


def test_course_completion_all_passed(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_comp_full@a.edu", first_name="F", last_name="U")
    admin_session.add(person)
    admin_session.flush()
    c = _seed_course(admin_session, tid, "cat-comp-full", "Full Course")
    _seed_chapter(admin_session, tid, c.id, 1)
    act = _seed_activity(admin_session, tid, c.id, 1, "Act")
    admin_session.flush()

    submit_activity(admin_session, tenant_id=tid, person_id=person.id, activity=act, answers={"q1": ["A"]})
    admin_session.flush()

    pct = course_completion(admin_session, tenant_id=tid, person_id=person.id, course_id=c.id)
    admin_session.rollback()
    assert pct == 100


def test_course_structure_parts_grouping(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_struct@a.edu", first_name="S", last_name="T")
    admin_session.add(person)
    admin_session.flush()
    c = _seed_course(admin_session, tid, "cat-struct", "Struct Course")
    # Part I: chapters 1, 2 — Part II: chapter 3
    _seed_chapter(admin_session, tid, c.id, 1, "Ch One", part="I", order_index=1)
    _seed_chapter(admin_session, tid, c.id, 2, "Ch Two", part="I", order_index=2)
    _seed_chapter(admin_session, tid, c.id, 3, "Ch Three", part="II", order_index=3)
    act1 = _seed_activity(admin_session, tid, c.id, 1, "Act 1")
    _seed_activity(admin_session, tid, c.id, 2, "Act 2")
    _seed_activity(admin_session, tid, c.id, 3, "Act 3")
    admin_session.flush()

    # Pass act1
    submit_activity(admin_session, tenant_id=tid, person_id=person.id, activity=act1, answers={"q1": ["A"]})
    admin_session.flush()

    structure = course_structure(admin_session, tenant_id=tid, person_id=person.id, course=c)

    # Extract all needed values while the session is active
    parts = structure["parts"]
    n_parts = len(parts)
    part0_label = parts[0]["part"]
    part1_label = parts[1]["part"]
    n_ch_part0 = len(parts[0]["chapters"])
    n_ch_part1 = len(parts[1]["chapters"])
    ch1_acts = parts[0]["chapters"][0]["activities"]
    ch1_act0_passed = ch1_acts[0]["passed"]
    ch1_act0_pct = ch1_acts[0]["pct"]

    admin_session.rollback()

    assert n_parts == 2
    assert part0_label == "I"
    assert part1_label == "II"
    assert n_ch_part0 == 2
    assert n_ch_part1 == 1
    assert ch1_act0_passed is True
    assert ch1_act0_pct == 100


def test_course_structure_continue_target(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_ct@a.edu", first_name="C", last_name="T")
    admin_session.add(person)
    admin_session.flush()
    c = _seed_course(admin_session, tid, "cat-ct", "CT Course")
    _seed_chapter(admin_session, tid, c.id, 1, part="I", order_index=1)
    _seed_chapter(admin_session, tid, c.id, 2, part="I", order_index=2)
    act1 = _seed_activity(admin_session, tid, c.id, 1, "Act 1")
    _seed_activity(admin_session, tid, c.id, 2, "Act 2")
    admin_session.flush()

    # Pass act1 → continue_target should be chapter 2
    submit_activity(admin_session, tenant_id=tid, person_id=person.id, activity=act1, answers={"q1": ["A"]})
    admin_session.flush()

    structure = course_structure(admin_session, tenant_id=tid, person_id=person.id, course=c)
    cont_number = structure["continue_target"].number if structure["continue_target"] else None
    admin_session.rollback()

    assert cont_number == 2


def test_course_structure_locked_when_prereq_unmet(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_lock@a.edu", first_name="L", last_name="K")
    admin_session.add(person)
    admin_session.flush()
    prereq = _seed_course(admin_session, tid, "cat-prereq", "Prereq Course")
    main_c = _seed_course(admin_session, tid, "cat-main", "Main Course")
    admin_session.add(
        CoursePrerequisite(tenant_id=tid, course_id=main_c.id, requires_course_id=prereq.id)
    )
    admin_session.flush()

    structure = course_structure(admin_session, tenant_id=tid, person_id=person.id, course=main_c)
    locked = structure["locked"]
    admin_session.rollback()
    assert locked is True


def test_course_structure_not_locked_without_prereq(admin_session, tenant_a):
    tid = tenant_a.id
    person = Person(tenant_id=tid, email="cat_nolock@a.edu", first_name="N", last_name="L")
    admin_session.add(person)
    c = _seed_course(admin_session, tid, "cat-nolock", "No Lock Course")
    admin_session.flush()

    structure = course_structure(admin_session, tenant_id=tid, person_id=person.id, course=c)
    locked = structure["locked"]
    admin_session.rollback()
    assert locked is False
