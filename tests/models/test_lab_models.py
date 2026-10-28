from uuid import uuid4

from dotmac_kernel.models import Party, PartyPerson, PartyType
from dotmac_learning import ActivityWrite, CourseWrite, create_activity, create_course

from app.models.lab import LabInstance, LabTemplate


def test_create_template_and_instance(admin_session, tenant_a):
    c = create_course(admin_session, CourseWrite(
        id=uuid4(), tenant_id=tenant_a.id, slug="foundation", title="F",
        discipline="networking", source_ref="x", version=1,
        status="published", listed=False,
    ))

    a = create_activity(admin_session, ActivityWrite(
        id=uuid4(), tenant_id=tenant_a.id, course_id=c.id, chapter_number=14, type="lab",
        title="VLAN lab", pass_threshold=0.6, assessment_mode="graded",
        grading="auto", weight=1.0,
    ))

    lt = LabTemplate(
        tenant_id=tenant_a.id, course_id=c.id, chapter_number=14, activity_id=a.id,
        slug="vlan", title="VLAN", topology="name: x", instructions_html="<p>do</p>",
        checks=[{"id": "c1", "type": "probe"}],
        seed_spec={"o": {"type": "int", "min": 2, "max": 9}},
        limits={"time_minutes": 45}, source_hash="abc", version=1)
    admin_session.add(lt); admin_session.flush()

    p = Party(tenant_id=tenant_a.id, party_type=PartyType.person, display_name="Lab Rat",
              email="learner@a.example.com", is_active=True)
    admin_session.add(p); admin_session.flush()
    admin_session.add(PartyPerson(party_id=p.id, first_name="Lab", last_name="Rat"))
    admin_session.flush()

    li = LabInstance(
        tenant_id=tenant_a.id, activity_id=a.id, person_id=p.id,
        instance_name="dal-x", seed={"o": 5}, status="queued", consoles={})
    admin_session.add(li); admin_session.flush()

    assert lt.activity_id == a.id
    assert li.status == "queued"
    assert lt.engine == "containerlab"
    # instructions_md is nullable — a row created without it (e.g. demo/seed
    # code that only supplies instructions_html) must not fail to insert.
    assert lt.instructions_md is None
    admin_session.rollback()


def test_lab_template_stores_instructions_md(admin_session, tenant_a):
    c = create_course(admin_session, CourseWrite(
        id=uuid4(), tenant_id=tenant_a.id, slug="foundation2", title="F",
        discipline="networking", source_ref="x", version=1,
        status="published", listed=False,
    ))

    a = create_activity(admin_session, ActivityWrite(
        id=uuid4(), tenant_id=tenant_a.id, course_id=c.id, chapter_number=14, type="lab",
        title="VLAN lab 2", pass_threshold=0.6, assessment_mode="graded",
        grading="auto", weight=1.0,
    ))

    lt = LabTemplate(
        tenant_id=tenant_a.id, course_id=c.id, chapter_number=14, activity_id=a.id,
        slug="vlan2", title="VLAN 2", topology="name: x", instructions_html="<p>do</p>",
        instructions_md="Do the thing at 10.0.{{lan_octet}}.10.",
        checks=[], seed_spec={}, limits={}, source_hash="abc", version=1)
    admin_session.add(lt); admin_session.flush()
    admin_session.refresh(lt)

    assert lt.instructions_md == "Do the thing at 10.0.{{lan_octet}}.10."
    admin_session.rollback()
