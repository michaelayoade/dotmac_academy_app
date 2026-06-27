"""TDD tests for the cross-tenant lab worker/reaper jobs (Task 7).

These jobs OWN their transaction (they ``commit``). The tests pass the conftest
``admin_session`` (a BYPASSRLS Session) directly into the functions rather than
opening a new admin connection, and clean up by letting ``tenant_a`` CASCADE.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from app.config import settings
from app.models.assessment import Activity
from app.models.course import Course
from app.models.lab import LabInstance, LabTemplate
from app.models.person import Person
from app.services import lab_jobs
from app.services.labengine.interface import LabHandle


def _seed(db, tid):
    c = Course(tenant_id=tid, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    db.add(c)
    db.flush()
    act = Activity(tenant_id=tid, course_id=c.id, chapter_number=14, type="lab",
                   title="VLAN Lab", pass_threshold=0.6)
    db.add(act)
    db.flush()
    lt = LabTemplate(
        tenant_id=tid, course_id=c.id, chapter_number=14, activity_id=act.id,
        slug="vlan", title="VLAN", topology="name: x {{o}}",
        instructions_html="<p>do</p>",
        checks=[{"id": "c1", "type": "probe"}],
        seed_spec={"o": {"type": "int", "min": 2, "max": 9}},
        limits={"time_minutes": 45},
    )
    db.add(lt)
    db.flush()
    p = Person(tenant_id=tid, email="trainee@example.com", first_name="T", last_name="U")
    db.add(p)
    db.flush()
    return c, act, lt, p


def test_drain_once_provisions_pending(admin_session, tenant_a, monkeypatch):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    monkeypatch.setattr(settings, "max_concurrent_labs", 20)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-drain", seed={"o": 5},
                       status="provisioning", consoles={})
    admin_session.add(inst)
    admin_session.commit()

    engine = MagicMock()
    engine.deploy.return_value = LabHandle(
        instance_name="dal-drain", nodes={"client": "clab-x-client"},
        mgmt={"client": "172.20.20.3"}, kinds={"client": "linux"})

    n = lab_jobs.drain_once(admin_session, engine)

    assert n == 1
    admin_session.refresh(inst)
    assert inst.status == "active"
    engine.deploy.assert_called_once()


def test_reap_idle_destroys_stale(admin_session, tenant_a):
    _c, act, lt, p = _seed(admin_session, tenant_a.id)
    inst = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
                       instance_name="dal-reap", seed={"o": 5},
                       status="active", consoles={},
                       last_active_at=datetime.now(UTC) - timedelta(minutes=999))
    admin_session.add(inst)
    admin_session.commit()

    engine = MagicMock()
    n = lab_jobs.reap_idle(admin_session, engine)

    assert n == 1
    admin_session.refresh(inst)
    assert inst.status == "reaped"
    engine.destroy.assert_called_once_with("dal-reap")
