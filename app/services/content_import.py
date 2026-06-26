"""Foundation manual content import service.

Parses markdown chapter files (with YAML frontmatter) into rendered HTML and
upserts them into the database as Course/Chapter records.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import markdown as md
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.course import Chapter, Course


def sync_figures(figures_dir: Path, static_figures_dir: Path) -> int:
    """Copy produced figure PNGs into the app's static/figures/ directory.

    Chapter HTML references figures at ``/static/figures/<id>.png``; produced
    figures live in the source ``figures_dir`` and must be copied into the
    served ``static/`` tree or they 404 in the browser. Returns the number of
    files copied. Safe to call repeatedly (overwrites).
    """
    figures_dir = Path(figures_dir)
    static_figures_dir = Path(static_figures_dir)
    if not figures_dir.is_dir():
        return 0
    static_figures_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for png in figures_dir.glob("*.png"):
        shutil.copy2(png, static_figures_dir / png.name)
        copied += 1
    return copied

# Matches the YAML frontmatter block at the top of a file.
_FM = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)

# Matches FIGURE callouts like: FIGURE `FND-01-09` *optional caption*
_FIG = re.compile(r"FIGURE `([A-Z0-9\-]+)`(?:\s*\*(.*?)\*)?")


@dataclass
class ChapterDoc:
    """Parsed representation of a chapter markdown file."""

    number: int
    title: str
    part: str
    body_html: str
    source_hash: str


def _figure_sub(figures_dir: Path):
    """Return a regex replacement function that substitutes FIGURE callouts."""

    def repl(m: re.Match) -> str:
        fid = m.group(1)
        caption = m.group(2) or ""
        img_path = figures_dir / f"{fid}.png"
        if img_path.exists():
            return (
                f'<figure>'
                f'<img src="/static/figures/{fid}.png" alt="{caption}">'
                f'<figcaption>{caption}</figcaption>'
                f'</figure>'
            )
        return (
            f'<figure class="placeholder">'
            f'<figcaption>[figure {fid} not yet produced] {caption}</figcaption>'
            f'</figure>'
        )

    return repl


def parse_chapter_file(path: Path, figures_dir: Path) -> ChapterDoc:
    """Parse a markdown chapter file into a ChapterDoc.

    Strips YAML frontmatter, substitutes FIGURE callouts, then renders the
    remaining markdown to HTML.

    Args:
        path: Path to the ``chapter-NN.md`` file.
        figures_dir: Directory to search for produced figure PNG files.

    Returns:
        A :class:`ChapterDoc` with rendered HTML and metadata from frontmatter.
    """
    raw = Path(path).read_text(encoding="utf-8")
    source_hash = hashlib.sha256(raw.encode()).hexdigest()

    fm_match = _FM.match(raw)
    meta: dict = yaml.safe_load(fm_match.group(1)) if fm_match else {}
    body_md = raw[fm_match.end():] if fm_match else raw

    # Substitute FIGURE callouts before markdown rendering so they become raw
    # HTML blocks (markdown won't re-process them).
    body_md = _FIG.sub(_figure_sub(figures_dir), body_md)

    body_html = md.markdown(body_md, extensions=["tables", "fenced_code"])

    return ChapterDoc(
        number=int(meta.get("chapter", 0)),
        title=str(meta.get("title", "")),
        part=str(meta.get("part", "")),
        body_html=body_html,
        source_hash=source_hash,
    )


def import_foundation(
    db: Session,
    *,
    tenant_id,
    chapters_dir: Path,
    figures_dir: Path,
) -> Course:
    """Upsert the Foundation course and its chapters from a directory of markdown files.

    Idempotent: chapters whose ``source_hash`` has not changed are skipped.
    ``Course.version`` is bumped only when at least one chapter changed or was added.

    Args:
        db: SQLAlchemy session (must have INSERT/UPDATE rights on courses/chapters).
        tenant_id: UUID of the tenant to import into.
        chapters_dir: Directory containing ``chapter-*.md`` files.
        figures_dir: Directory containing produced figure PNG files.

    Returns:
        The upserted :class:`Course` for the Foundation manual.
    """
    course = db.scalars(
        select(Course)
        .where(Course.tenant_id == tenant_id)
        .where(Course.slug == "foundation")
    ).first()

    if course is None:
        course = Course(
            tenant_id=tenant_id,
            slug="foundation",
            title="Foundation",
            discipline="networking",
            source_ref="foundation@0.1.0",
            version=1,
        )
        db.add(course)
        db.flush()

    changed = False

    for chapter_file in sorted(Path(chapters_dir).glob("chapter-*.md")):
        doc = parse_chapter_file(chapter_file, figures_dir)

        existing = db.scalars(
            select(Chapter)
            .where(Chapter.tenant_id == tenant_id)
            .where(Chapter.course_id == course.id)
            .where(Chapter.number == doc.number)
        ).first()

        if existing is None:
            db.add(
                Chapter(
                    tenant_id=tenant_id,
                    course_id=course.id,
                    number=doc.number,
                    title=doc.title,
                    part=doc.part,
                    body_html=doc.body_html,
                    source_hash=doc.source_hash,
                    order_index=doc.number,
                )
            )
            changed = True
        elif existing.source_hash != doc.source_hash:
            existing.title = doc.title
            existing.part = doc.part
            existing.body_html = doc.body_html
            existing.source_hash = doc.source_hash
            changed = True
        # else: unchanged — skip

    if changed:
        course.version += 1

    db.flush()
    return course
