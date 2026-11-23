"""Fast presentation checks; no database or deployed-schema acceptance claim."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader, select_autoescape

from app.services.training_pages import COURSE_COPY, TrainingCopy, public_training_pages, training_page

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def environment() -> Environment:
    # Kernel owns production rendering. This isolated fixture only verifies
    # product markup, with the shared theme head deliberately stubbed out.
    return Environment(
        loader=ChoiceLoader(
            [
                DictLoader({"_dotmac_ui_head.html": ""}),
                FileSystemLoader(ROOT / "templates"),
            ]
        ),
        autoescape=select_autoescape(["html"]),
    )


def test_copy_has_unique_stable_public_paths() -> None:
    paths = [
        page.path
        for copy in COURSE_COPY
        if (page := training_page(title=copy.course_title, chapter_count=5, discipline="management"))
    ]
    assert len(paths) == len(set(paths)) == 21
    assert paths.count("/fibre-optic-training") == 1
    assert "/training/fibre-optic-training" not in paths
    assert training_page(title="Unreviewed course", chapter_count=2, discipline="technical") is None


@pytest.mark.parametrize("copy", COURSE_COPY, ids=lambda copy: copy.slug)
def test_course_markup_has_metadata_and_correct_enrolment(environment: Environment, copy: TrainingCopy) -> None:
    management = copy in COURSE_COPY[12:]
    page = training_page(
        title=copy.course_title,
        chapter_count=7,
        discipline="management" if management else "technical",
    )
    assert page is not None
    rendered = environment.get_template("public/course_training.html").render(page=page)
    assert f'<link rel="canonical" href="{page.canonical_url}">' in rendered
    assert '<meta name="description"' in rendered
    assert "7 chapters" in rendered
    assert "final assessment" in rendered
    if management:
        assert "Enquire about this course" in rendered
        assert "Free technical training is available" not in rendered
    else:
        assert "Apply for technical training" in rendered
        assert "eligible applicants" in rendered
    assert "/courses/" not in rendered  # No private course-content links.


@dataclass(frozen=True)
class ListedCourse:
    title: str
    slug: str
    discipline: str


@dataclass(frozen=True)
class ListedItem:
    course: ListedCourse
    chapter_count: int


def test_public_pages_follow_current_owner_results_and_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = uuid4()
    db = object()
    listed = [ListedItem(ListedCourse("Network Support", "private-course-slug", "technical"), 16)]

    def owner_catalog(actual_db: object, *, tenant_id: UUID) -> tuple[ListedItem, ...]:
        assert actual_db is db
        assert tenant_id == expected_tenant
        return tuple(listed)

    expected_tenant = tenant_id
    monkeypatch.setitem(sys.modules, "dotmac_learning", SimpleNamespace(public_catalog=owner_catalog))
    pages = public_training_pages(db, tenant_id=tenant_id)
    assert len(pages) == 1
    assert pages[0].path == "/training/network-support"
    assert pages[0].chapter_count == 16
    listed.clear()  # Unlisting through Learning removes the page without repair.
    assert public_training_pages(db, tenant_id=tenant_id) == ()


def test_catalogue_links_only_courses_with_public_copy(environment: Environment) -> None:
    technical = ListedCourse("Network Support", "network-support", "technical")
    unknown = ListedCourse("Future course", "future-course", "technical")
    management = ListedCourse("Sales Essentials", "sales", "management")
    pages = {
        course.title: training_page(title=course.title, chapter_count=6, discipline=course.discipline)
        for course in (technical, management)
    }
    rendered = environment.get_template("public/courses.html").render(
        tech=[{"course": technical, "chapter_count": 16}, {"course": unknown, "chapter_count": 4}],
        mgmt=[{"course": management, "chapter_count": 5}],
        training_pages=pages,
    )
    assert 'href="/training/network-support"' in rendered
    assert 'href="/training/sales-essentials"' in rendered
    assert "Future course" in rendered
    assert "/training/future-course" not in rendered


def test_course_copy_is_escaped(environment: Environment) -> None:
    from app.services.training_pages import TrainingCopy, TrainingPage

    page = TrainingPage(TrainingCopy("Example", "example", '<script>alert("x")</script>', '"<unsafe>'), 1, False)
    rendered = environment.get_template("public/course_training.html").render(page=page)
    assert "<script>" not in rendered
    assert "&lt;unsafe&gt;" in rendered
