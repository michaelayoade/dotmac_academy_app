from app.models.assessment import Activity
from app.models.course import Course
from app.models.lab import LabInstance, LabTemplate
from app.models.person import Person


def test_create_template_and_instance(admin_session, tenant_a):
    c = Course(tenant_id=tenant_a.id, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    admin_session.add(c); admin_session.flush()

    a = Activity(tenant_id=tenant_a.id, course_id=c.id, chapter_number=14, type="lab",
                 title="VLAN lab", pass_threshold=0.6)
    admin_session.add(a); admin_session.flush()

    lt = LabTemplate(
        tenant_id=tenant_a.id, course_id=c.id, chapter_number=14, activity_id=a.id,
        slug="vlan", title="VLAN", topology="name: x", instructions_html="<p>do</p>",
        checks=[{"id": "c1", "type": "probe"}],
        seed_spec={"o": {"type": "int", "min": 2, "max": 9}},
        limits={"time_minutes": 45}, source_hash="abc", version=1)
    admin_session.add(lt); admin_session.flush()

    p = Person(tenant_id=tenant_a.id, email="learner@a.example.com",
               first_name="Lab", last_name="Rat")
    admin_session.add(p); admin_session.flush()

    li = LabInstance(
        tenant_id=tenant_a.id, activity_id=a.id, person_id=p.id,
        instance_name="dal-x", seed={"o": 5}, status="queued", consoles={})
    admin_session.add(li); admin_session.flush()

    assert lt.activity_id == a.id
    assert li.status == "queued"
    assert lt.engine == "containerlab"
    admin_session.rollback()
