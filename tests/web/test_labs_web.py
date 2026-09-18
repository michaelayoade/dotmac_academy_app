"""Task 9 — student lab portal (htmx): launch / status / check / reset.

The lab engine is mocked so neither provisioning nor grading touch real Docker.
We monkeypatch ``app.web.labs.ContainerlabEngine`` with a fake whose ``exec``
returns a passing :class:`ExecResult`, so the seeded command check passes.
"""

from __future__ import annotations

from app.models.assessment import Activity, Score, Submission
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Course
from app.models.lab import LabInstance, LabTemplate
from app.models.offering import CourseOffering
from app.models.person import Person
from app.services.labengine.interface import ExecResult, LabHandle
from app.services.security import hash_password


class _FakeEngine:
    """Stand-in for ContainerlabEngine — never shells out."""

    def __init__(self, workdir):
        self.workdir = workdir

    def deploy(self, topology_text, instance_name):
        return LabHandle(
            instance_name=instance_name,
            nodes={"r1": f"clab-{instance_name}-r1"},
            mgmt={"r1": "172.20.20.3"},
            kinds={"r1": "linux"},
        )

    def reset(self, topology_text, instance_name):
        return self.deploy(topology_text, instance_name)

    def destroy(self, instance_name):
        return None

    def exec(self, handle, node, command):
        return ExecResult(stdout="ok", stderr="", exit_code=0)

    def ssh_exec(self, handle, node, command, user="admin", password=""):
        return ExecResult(stdout="ok", stderr="", exit_code=0)

    def status(self, instance_name):
        return "running"

    def console_target(self, handle, node):
        return handle.nodes[node]


class _FailingResetEngine(_FakeEngine):
    """A fake engine whose reset() always fails, for the guarded-reset test."""

    def reset(self, topology_text, instance_name):
        raise RuntimeError("containerlab reset failed")


def _make_person(admin_session, tenant, email: str) -> Person:
    p = Person(tenant_id=tenant.id, email=email, first_name="S", last_name="L")
    admin_session.add(p)
    admin_session.flush()
    admin_session.add(
        UserCredential(
            tenant_id=tenant.id,
            person_id=p.id,
            email=email,
            password_hash=hash_password("password1"),
        )
    )
    admin_session.commit()
    return p


def _login(app_client, email: str) -> dict[str, str]:
    h = {"Host": "alpha.localhost"}
    app_client.post("/login", headers=h, data={"email": email, "password": "password1"})
    return h


def _entitle(admin_session, tenant, person, course):
    """Give the person access to the course via cohort + enrollment + offering."""
    coh = Cohort(tenant_id=tenant.id, name="Lab Cohort", discipline=course.discipline,
                 status="active")
    admin_session.add(coh)
    admin_session.flush()
    admin_session.add(Enrollment(tenant_id=tenant.id, cohort_id=coh.id, person_id=person.id,
                                 role_in_cohort="student", status="active"))
    admin_session.add(CourseOffering(tenant_id=tenant.id, cohort_id=coh.id, course_id=course.id,
                                     status="active"))
    admin_session.commit()
    return coh


def _seed_lab(admin_session, tenant, *, with_course=True):
    course = Course(
        tenant_id=tenant.id,
        slug="foundation",
        title="F",
        discipline="networking",
        source_ref="x",
        version=1,
    )
    admin_session.add(course)
    admin_session.flush()
    act = Activity(
        tenant_id=tenant.id,
        course_id=course.id,
        chapter_number=14,
        type="lab",
        title="VLAN Lab",
        pass_threshold=0.5,
    )
    admin_session.add(act)
    admin_session.flush()
    tpl = LabTemplate(
        tenant_id=tenant.id,
        course_id=course.id,
        chapter_number=14,
        activity_id=act.id,
        slug="vlan",
        title="VLAN Lab",
        topology="name: x",
        instructions_html="<p>Configure the router.</p>",
        checks=[
            {
                "id": "c1",
                "type": "command",
                "node": "r1",
                "command": "true",
                "assert": {"exit_code": 0},
            }
        ],
        seed_spec={},
        limits={},
        source_hash="abc",
        version=1,
    )
    admin_session.add(tpl)
    admin_session.commit()
    return course, act, tpl


def _seed_seeded_lab(admin_session, tenant):
    """A lab template whose instructions carry a `{{lan_octet}}` placeholder,
    for the interpolation/placeholder web tests."""
    course = Course(
        tenant_id=tenant.id, slug="foundation-seeded", title="F", discipline="networking",
        source_ref="x", version=1,
    )
    admin_session.add(course)
    admin_session.flush()
    act = Activity(
        tenant_id=tenant.id, course_id=course.id, chapter_number=14, type="lab",
        title="Seeded Lab", pass_threshold=0.5,
    )
    admin_session.add(act)
    admin_session.flush()
    tpl = LabTemplate(
        tenant_id=tenant.id, course_id=course.id, chapter_number=14, activity_id=act.id,
        slug="seeded", title="Seeded Lab", topology="name: x",
        instructions_html="<p>Configure the client at 10.0.{{lan_octet}}.10.</p>",
        instructions_md="Configure the client at 10.0.{{lan_octet}}.10.",
        checks=[], seed_spec={"lan_octet": {"type": "int", "min": 2, "max": 9}},
        limits={}, source_hash="abc", version=1,
    )
    admin_session.add(tpl)
    admin_session.commit()
    return course, act, tpl


def _csrf(app_client, path, h):
    r = app_client.get(path, headers=h)
    return r, app_client.cookies.get("csrf_token") or r.cookies.get("csrf_token", "")


def test_dropped_owner_loses_live_instance_access(app_client, admin_session, tenant_a, monkeypatch):
    """Revocation propagates to live instances: a dropped owner is 403 on status/check."""
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "drop@a.edu")
    course, act, _ = _seed_lab(admin_session, tenant_a)
    coh = _entitle(admin_session, tenant_a, p, course)
    h = _login(app_client, "drop@a.edu")
    # Launch while entitled.
    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    app_client.post(f"/labs/{act.id}/launch", headers={**h, "x-csrf-token": csrf})
    inst = admin_session.query(LabInstance).filter(
        LabInstance.activity_id == act.id, LabInstance.person_id == p.id).one()

    # Instructor drops the learner; the live instance must now be off-limits.
    enr = admin_session.query(Enrollment).filter(
        Enrollment.cohort_id == coh.id, Enrollment.person_id == p.id).one()
    enr.status = "dropped"
    admin_session.commit()

    assert app_client.get(f"/labs/instances/{inst.id}/status", headers=h).status_code == 403
    r = app_client.post(f"/labs/instances/{inst.id}/check", headers={**h, "x-csrf-token": csrf})
    assert r.status_code == 403


def test_unentitled_student_forbidden_on_lab(app_client, admin_session, tenant_a, monkeypatch):
    """Slice 1: no offering for the lab's course → 403 on detail and launch, no instance."""
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    _make_person(admin_session, tenant_a, "nolab@a.edu")
    _, act, _ = _seed_lab(admin_session, tenant_a)  # no enrollment/offering
    h = _login(app_client, "nolab@a.edu")
    assert app_client.get(f"/labs/{act.id}", headers=h).status_code == 403
    csrf = app_client.cookies.get("csrf_token", "")
    r = app_client.post(f"/labs/{act.id}/launch", headers={**h, "x-csrf-token": csrf})
    assert r.status_code == 403
    n = admin_session.query(LabInstance).filter(LabInstance.activity_id == act.id).count()
    assert n == 0


def test_launch_creates_instance_and_returns_status(
    app_client, admin_session, tenant_a, monkeypatch
):
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "owner@a.edu")
    course, act, _ = _seed_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    h = _login(app_client, "owner@a.edu")

    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    r = app_client.post(
        f"/labs/{act.id}/launch", headers={**h, "x-csrf-token": csrf}
    )
    assert r.status_code == 200
    assert "Status" in r.text

    rows = (
        admin_session.query(LabInstance)
        .filter(LabInstance.activity_id == act.id, LabInstance.person_id == p.id)
        .all()
    )
    assert len(rows) == 1
    assert rows[0].status in ("queued", "provisioning")


def test_check_grades_and_writes_score(app_client, admin_session, tenant_a, monkeypatch):
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "owner2@a.edu")
    course, act, _ = _seed_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    h = _login(app_client, "owner2@a.edu")

    # Launch, then simulate the worker bringing the instance up (active + consoles).
    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    app_client.post(f"/labs/{act.id}/launch", headers={**h, "x-csrf-token": csrf})
    inst = (
        admin_session.query(LabInstance)
        .filter(LabInstance.activity_id == act.id, LabInstance.person_id == p.id)
        .one()
    )
    inst.status = "active"
    inst.consoles = {"r1": {"kind": "linux", "mgmt": "172.20.20.3"}}
    admin_session.commit()

    r = app_client.post(
        f"/labs/instances/{inst.id}/check", headers={**h, "x-csrf-token": csrf}
    )
    assert r.status_code == 200
    assert "score" in r.text.lower()

    score = (
        admin_session.query(Score)
        .join(Submission, Score.submission_id == Submission.id)
        .filter(Submission.activity_id == act.id, Submission.person_id == p.id)
        .one()
    )
    assert score.source == "auto"
    assert score.max_score > 0
    assert score.passed is True


def test_cross_person_check_forbidden(app_client, admin_session, tenant_a, monkeypatch):
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    owner = _make_person(admin_session, tenant_a, "owner3@a.edu")
    _make_person(admin_session, tenant_a, "intruder@a.edu")
    _, act, _ = _seed_lab(admin_session, tenant_a)
    inst = LabInstance(
        tenant_id=tenant_a.id,
        activity_id=act.id,
        person_id=owner.id,
        instance_name="dal-x",
        seed={},
        status="active",
        consoles={"r1": {"kind": "linux", "mgmt": "172.20.20.3"}},
    )
    admin_session.add(inst)
    admin_session.commit()
    admin_session.refresh(inst)

    h = _login(app_client, "intruder@a.edu")
    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    r = app_client.post(
        f"/labs/instances/{inst.id}/check", headers={**h, "x-csrf-token": csrf}
    )
    assert r.status_code == 403


def test_cross_tenant_check_not_found(
    app_client, admin_session, tenant_a, tenant_b, monkeypatch
):
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    _make_person(admin_session, tenant_a, "owner4@a.edu")
    p_b = Person(tenant_id=tenant_b.id, email="b@b.edu", first_name="B", last_name="B")
    admin_session.add(p_b)
    admin_session.flush()
    _, act_b, _ = _seed_lab(admin_session, tenant_b)
    inst = LabInstance(
        tenant_id=tenant_b.id,
        activity_id=act_b.id,
        person_id=p_b.id,
        instance_name="dal-y",
        seed={},
        status="active",
        consoles={"r1": {"kind": "linux", "mgmt": "172.20.20.3"}},
    )
    admin_session.add(inst)
    admin_session.commit()
    admin_session.refresh(inst)

    h = _login(app_client, "owner4@a.edu")
    _, csrf = _csrf(app_client, f"/labs/{act_b.id}", h)
    # tenant_a user hitting tenant_b's instance route → 404.
    r = app_client.post(
        f"/labs/instances/{inst.id}/check", headers={**h, "x-csrf-token": csrf}
    )
    assert r.status_code == 404


def test_detail_shows_neutral_placeholder_before_launch(app_client, admin_session, tenant_a, monkeypatch):
    """No instance yet → a neutral placeholder, never raw/unfilled instructions."""
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "prelaunch@a.edu")
    course, act, _tpl = _seed_seeded_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    h = _login(app_client, "prelaunch@a.edu")

    r = app_client.get(f"/labs/{act.id}", headers=h)
    assert r.status_code == 200
    assert "{{lan_octet}}" not in r.text
    assert "Launch the lab" in r.text


def test_detail_after_launch_interpolates_this_instances_seed(app_client, admin_session, tenant_a, monkeypatch):
    """Once an instance exists, GET renders instructions substituted with THAT
    instance's seed — no literal placeholder left in the page."""
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "postlaunch@a.edu")
    course, act, _tpl = _seed_seeded_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    h = _login(app_client, "postlaunch@a.edu")

    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    launch_resp = app_client.post(f"/labs/{act.id}/launch", headers={**h, "x-csrf-token": csrf})
    assert launch_resp.headers.get("HX-Refresh") == "true"

    inst = (
        admin_session.query(LabInstance)
        .filter(LabInstance.activity_id == act.id, LabInstance.person_id == p.id)
        .one()
    )
    r = app_client.get(f"/labs/{act.id}", headers=h)
    assert r.status_code == 200
    assert "{{lan_octet}}" not in r.text
    assert f"10.0.{inst.seed['lan_octet']}.10" in r.text


def test_two_learners_same_template_get_different_rendered_instructions(
    app_client, admin_session, tenant_a, monkeypatch
):
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p1 = _make_person(admin_session, tenant_a, "learner1@a.edu")
    p2 = _make_person(admin_session, tenant_a, "learner2@a.edu")
    course, act, tpl = _seed_seeded_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p1, course)
    _entitle(admin_session, tenant_a, p2, course)

    inst1 = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p1.id,
                        instance_name="dal-l1", seed={"lan_octet": 2}, status="active",
                        consoles={})
    inst2 = LabInstance(tenant_id=tenant_a.id, activity_id=act.id, person_id=p2.id,
                        instance_name="dal-l2", seed={"lan_octet": 8}, status="active",
                        consoles={})
    admin_session.add(inst1)
    admin_session.add(inst2)
    admin_session.commit()

    h1 = _login(app_client, "learner1@a.edu")
    h2 = _login(app_client, "learner2@a.edu")
    r1 = app_client.get(f"/labs/{act.id}", headers=h1)
    r2 = app_client.get(f"/labs/{act.id}", headers=h2)
    assert "10.0.2.10" in r1.text
    assert "10.0.8.10" in r2.text
    assert r1.text != r2.text


def test_reset_success_returns_status_partial(app_client, admin_session, tenant_a, monkeypatch):
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "reset-ok@a.edu")
    course, act, _ = _seed_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    inst = LabInstance(
        tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
        instance_name="dal-reset-ok", seed={}, status="error", error="stale",
        consoles={"r1": {"kind": "linux", "mgmt": "172.20.20.3"}},
    )
    admin_session.add(inst)
    admin_session.commit()
    admin_session.refresh(inst)

    h = _login(app_client, "reset-ok@a.edu")
    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    r = app_client.post(f"/labs/instances/{inst.id}/reset", headers={**h, "x-csrf-token": csrf})
    assert r.status_code == 200
    admin_session.refresh(inst)
    assert inst.status == "active"
    assert inst.error is None


def test_reset_endpoint_with_failing_engine_returns_200_with_error_partial(
    app_client, admin_session, tenant_a, monkeypatch
):
    """A failing engine.reset() must not become an unhandled 500 — the route
    still returns 200 with the status partial showing the error state."""
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FailingResetEngine)
    p = _make_person(admin_session, tenant_a, "reset-fail@a.edu")
    course, act, _ = _seed_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    inst = LabInstance(
        tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
        instance_name="dal-reset-fail", seed={}, status="active",
        consoles={"r1": {"kind": "linux", "mgmt": "172.20.20.3"}},
    )
    admin_session.add(inst)
    admin_session.commit()
    admin_session.refresh(inst)

    h = _login(app_client, "reset-fail@a.edu")
    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    r = app_client.post(f"/labs/instances/{inst.id}/reset", headers={**h, "x-csrf-token": csrf})
    assert r.status_code == 200
    assert "containerlab reset failed" in r.text
    admin_session.refresh(inst)
    assert inst.status == "error"
    assert inst.error == "containerlab reset failed"


def test_reset_on_reaped_instance_is_refused(app_client, admin_session, tenant_a, monkeypatch):
    """A destroyed (reaped) instance must not be resurrected by reset()."""
    monkeypatch.setattr("app.web.labs.ContainerlabEngine", _FakeEngine)
    p = _make_person(admin_session, tenant_a, "reset-reaped@a.edu")
    course, act, _ = _seed_lab(admin_session, tenant_a)
    _entitle(admin_session, tenant_a, p, course)
    inst = LabInstance(
        tenant_id=tenant_a.id, activity_id=act.id, person_id=p.id,
        instance_name="dal-reaped", seed={}, status="reaped", consoles={},
    )
    admin_session.add(inst)
    admin_session.commit()
    admin_session.refresh(inst)

    h = _login(app_client, "reset-reaped@a.edu")
    _, csrf = _csrf(app_client, f"/labs/{act.id}", h)
    r = app_client.post(f"/labs/instances/{inst.id}/reset", headers={**h, "x-csrf-token": csrf})
    assert r.status_code == 409
    admin_session.refresh(inst)
    assert inst.status == "reaped"
