"""TDD tests for the Foundation content import service."""

from pathlib import Path
from app.services.content_import import parse_chapter_file, import_foundation, import_manual
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


def test_import_manual_custom_slug_distinct_from_foundation(admin_session, tenant_a):
    found = import_foundation(admin_session, tenant_id=tenant_a.id,
                              chapters_dir=FX / "chapters", figures_dir=FX / "figures" / "final")
    fiber = import_manual(admin_session, tenant_id=tenant_a.id, slug="fiber-engineering",
                          title="Fiber Engineering", discipline="fiber",
                          source_ref="fiber-engineering@0.1.0",
                          chapters_dir=FX / "chapters", figures_dir=FX / "figures" / "final")
    admin_session.flush()
    # Distinct course with the requested identity, imported alongside Foundation.
    assert fiber.id != found.id
    assert fiber.slug == "fiber-engineering"
    assert fiber.title == "Fiber Engineering"
    assert fiber.discipline == "fiber"
    assert admin_session.query(Course).filter(Course.tenant_id == tenant_a.id).count() == 2
    # Idempotent re-import returns the same course.
    again = import_manual(admin_session, tenant_id=tenant_a.id, slug="fiber-engineering",
                          title="Fiber Engineering", discipline="fiber",
                          source_ref="fiber-engineering@0.1.0",
                          chapters_dir=FX / "chapters", figures_dir=FX / "figures" / "final")
    assert again.id == fiber.id
    admin_session.rollback()
