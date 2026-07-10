"""TDD tests for the Foundation content import service."""

from pathlib import Path

import pytest

from app.models.course import Chapter, Course
from app.services.content_import import (
    import_foundation,
    import_manual,
    missing_figure_refs,
    parse_chapter_file,
)

FX = Path(__file__).resolve().parent.parent / "fixtures" / "manual"


def test_parse_chapter_strips_frontmatter_and_renders():
    doc = parse_chapter_file(FX / "chapters" / "chapter-01.md", FX / "figures" / "final")
    assert doc.number == 1 and doc.title == "Welcome" and doc.part == "I"
    assert "<h1>" in doc.body_html and "manual: foundation" not in doc.body_html
    assert "placeholder" in doc.body_html  # missing figure → placeholder


def test_import_is_idempotent(admin_session, tenant_a):
    c1 = import_foundation(
        admin_session,
        tenant_id=tenant_a.id,
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    admin_session.flush()
    n1 = admin_session.query(Chapter).filter(Chapter.course_id == c1.id).count()
    c2 = import_foundation(
        admin_session,
        tenant_id=tenant_a.id,
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    admin_session.flush()
    n2 = admin_session.query(Chapter).filter(Chapter.course_id == c2.id).count()
    assert c1.id == c2.id and n1 == n2 == 1
    assert c2.title == "Network Foundation"
    admin_session.rollback()


def test_import_manual_custom_slug_distinct_from_foundation(admin_session, tenant_a):
    found = import_foundation(
        admin_session,
        tenant_id=tenant_a.id,
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    fiber = import_manual(
        admin_session,
        tenant_id=tenant_a.id,
        slug="fiber-engineering",
        title="Technical Academy — Fiber Engineering",
        discipline="fiber",
        source_ref="fiber-engineering@0.1.0",
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    admin_session.flush()
    # Distinct course with the requested identity, imported alongside Foundation.
    assert fiber.id != found.id
    assert fiber.slug == "fiber-engineering"
    assert fiber.title == "Fiber Engineering"
    assert fiber.discipline == "fiber"
    assert admin_session.query(Course).filter(Course.tenant_id == tenant_a.id).count() == 2
    # Idempotent re-import returns the same course.
    again = import_manual(
        admin_session,
        tenant_id=tenant_a.id,
        slug="fiber-engineering",
        title="Fiber Engineering",
        discipline="fiber",
        source_ref="fiber-engineering@0.1.0",
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    assert again.id == fiber.id
    admin_session.rollback()


def test_import_rejects_missing_figures_by_default():
    missing = missing_figure_refs(FX / "chapters", FX / "figures" / "final")
    assert missing == {"chapter-01.md": ["FND-01-09"]}
    with pytest.raises(ValueError, match="FND-01-09"):
        import_foundation(
            None,
            tenant_id="tenant-id",
            chapters_dir=FX / "chapters",
            figures_dir=FX / "figures" / "final",
        )


def test_metadata_reimport_bumps_version(admin_session, tenant_a):
    course = import_manual(
        admin_session,
        tenant_id=tenant_a.id,
        slug="fiber-engineering",
        title="Fiber Engineering",
        discipline="fiber",
        source_ref="fiber@0.1.0",
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    admin_session.flush()
    v1 = course.version

    again = import_manual(
        admin_session,
        tenant_id=tenant_a.id,
        slug="fiber-engineering",
        title="Technical Academy — Fiber Engineering",
        discipline="networking",
        source_ref="fiber@0.2.0",
        chapters_dir=FX / "chapters",
        figures_dir=FX / "figures" / "final",
        strict_figures=False,
    )
    admin_session.flush()

    assert again.version == v1 + 1
    assert again.discipline == "networking"
    assert again.source_ref == "fiber@0.2.0"
    admin_session.rollback()
