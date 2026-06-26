"""TDD tests for the Foundation content import service."""

from pathlib import Path
from app.services.content_import import parse_chapter_file, import_foundation
from app.models.course import Course, Chapter

FX = Path(__file__).resolve().parent.parent / "fixtures" / "manual"


def test_parse_chapter_strips_frontmatter_and_renders():
    doc = parse_chapter_file(FX / "chapters" / "chapter-01.md", FX / "figures" / "final")
    assert doc.number == 1 and doc.title == "Welcome" and doc.part == "I"
    assert "<h1>" in doc.body_html and "manual: foundation" not in doc.body_html
    assert "placeholder" in doc.body_html  # missing figure → placeholder


def test_import_is_idempotent(admin_session, tenant_a):
    c1 = import_foundation(admin_session, tenant_id=tenant_a.id,
                           chapters_dir=FX / "chapters", figures_dir=FX / "figures" / "final")
    admin_session.flush()
    n1 = admin_session.query(Chapter).filter(Chapter.course_id == c1.id).count()
    c2 = import_foundation(admin_session, tenant_id=tenant_a.id,
                           chapters_dir=FX / "chapters", figures_dir=FX / "figures" / "final")
    admin_session.flush()
    n2 = admin_session.query(Chapter).filter(Chapter.course_id == c2.id).count()
    assert c1.id == c2.id and n1 == n2 == 1
    admin_session.rollback()
