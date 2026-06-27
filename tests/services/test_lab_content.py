"""TDD tests for the labs-as-code loader (Task 5)."""

from pathlib import Path

from app.models.assessment import Activity
from app.models.course import Course
from app.models.lab import LabTemplate
from app.services.lab_content import import_labs, parse_lab

LAB_YAML = """\
slug: vlan-segmentation
title: VLAN Segmentation
chapter_ref: 14
topology: topo.clab.yml
instructions: instructions.md
seed_spec:
  lan_octet:
    type: int
    min: 2
    max: 9
limits:
  time_minutes: 45
  ready_wait_seconds: 120
checks:
  - id: c1
    type: probe
    node: client
    weight: 1
    probe: ping
  - id: c2
    type: config_grep
    node: router
    weight: 1
    file: /etc/config
    contains: vlan
"""

TOPO = """\
name: vlan
topology:
  nodes:
    router:
      kind: vr-ros
    client:
      kind: linux
"""

INSTRUCTIONS = """\
# VLAN Segmentation

Configure the LAN.

$include: chapter-14.md#vlan-basics

Good luck.
"""

CHAPTER = """\
# Chapter 14

## Learning objectives

stuff

## VLAN basics

A VLAN is a virtual LAN.

It segments broadcast domains.

## Next section

other content
"""


def _make_lab_dir(tmp_path: Path) -> Path:
    lab = tmp_path / "labs" / "03-vlan-segmentation"
    lab.mkdir(parents=True)
    (lab / "lab.yaml").write_text(LAB_YAML, encoding="utf-8")
    (lab / "topo.clab.yml").write_text(TOPO, encoding="utf-8")
    (lab / "instructions.md").write_text(INSTRUCTIONS, encoding="utf-8")
    chapters = tmp_path / "chapters"
    chapters.mkdir()
    (chapters / "chapter-14.md").write_text(CHAPTER, encoding="utf-8")
    return tmp_path


def test_parse_lab(tmp_path):
    root = _make_lab_dir(tmp_path)
    spec = parse_lab(root / "labs" / "03-vlan-segmentation", chapters_dir=root / "chapters")
    assert spec.slug == "vlan-segmentation"
    assert spec.title == "VLAN Segmentation"
    assert spec.chapter_number == 14
    assert spec.checks[0]["type"] == "probe"
    assert "kind: vr-ros" in spec.topology_text
    assert "Configure the LAN." in spec.instructions_md
    assert spec.seed_spec["lan_octet"]["max"] == 9
    assert spec.limits["time_minutes"] == 45


def test_parse_lab_resolves_include(tmp_path):
    root = _make_lab_dir(tmp_path)
    spec = parse_lab(root / "labs" / "03-vlan-segmentation", chapters_dir=root / "chapters")
    # The anchored chapter slice is spliced in, not the whole chapter.
    assert "A VLAN is a virtual LAN." in spec.instructions_md
    assert "Learning objectives" not in spec.instructions_md
    assert "other content" not in spec.instructions_md
    # The $include directive line itself is gone.
    assert "$include" not in spec.instructions_md


def test_parse_lab_missing_include_does_not_crash(tmp_path):
    root = _make_lab_dir(tmp_path)
    (root / "labs" / "03-vlan-segmentation" / "instructions.md").write_text(
        "intro\n$include: nope.md#whatever\nend\n", encoding="utf-8"
    )
    spec = parse_lab(root / "labs" / "03-vlan-segmentation", chapters_dir=root / "chapters")
    assert "intro" in spec.instructions_md and "end" in spec.instructions_md


def _course(db, tenant_id):
    c = Course(tenant_id=tenant_id, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    db.add(c)
    db.flush()
    return c


def test_import_labs_creates_activity_and_template(admin_session, tenant_a, tmp_path):
    root = _make_lab_dir(tmp_path)
    c = _course(admin_session, tenant_a.id)
    templates = import_labs(
        admin_session, tenant_id=tenant_a.id, course_id=c.id,
        labs_dir=root / "labs", chapters_dir=root / "chapters",
    )
    admin_session.flush()
    assert len(templates) == 1
    lt = templates[0]
    assert lt.slug == "vlan-segmentation"

    activities = admin_session.query(Activity).filter(
        Activity.course_id == c.id, Activity.type == "lab"
    ).all()
    assert len(activities) == 1
    assert activities[0].id == lt.activity_id
    assert activities[0].bank_id is None
    assert lt.instructions_html.startswith("<")
    admin_session.rollback()


def test_import_labs_is_idempotent(admin_session, tenant_a, tmp_path):
    root = _make_lab_dir(tmp_path)
    c = _course(admin_session, tenant_a.id)
    t1 = import_labs(admin_session, tenant_id=tenant_a.id, course_id=c.id,
                     labs_dir=root / "labs", chapters_dir=root / "chapters")
    admin_session.flush()
    v1 = t1[0].version
    t2 = import_labs(admin_session, tenant_id=tenant_a.id, course_id=c.id,
                     labs_dir=root / "labs", chapters_dir=root / "chapters")
    admin_session.flush()
    assert t1[0].id == t2[0].id
    assert t2[0].version == v1
    assert admin_session.query(LabTemplate).filter(LabTemplate.course_id == c.id).count() == 1
    assert admin_session.query(Activity).filter(
        Activity.course_id == c.id, Activity.type == "lab"
    ).count() == 1
    admin_session.rollback()
