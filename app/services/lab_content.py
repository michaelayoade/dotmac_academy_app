"""Labs-as-code loader (Task 5).

Parses on-disk lab definitions (``lab.yaml`` + ``topo.clab.yml`` +
``instructions.md``) into :class:`LabSpec` dataclasses and upserts them into the
database as ``Activity(type="lab")`` + :class:`LabTemplate` pairs.

``lab.yaml`` schema (flat top-level keys; a ``lab:`` wrapper is also accepted)::

    slug: vlan-segmentation        # or `id`
    title: VLAN Segmentation
    chapter_ref: 14                # or `chapter_number`
    topology: topo.clab.yml        # file, relative to the lab dir
    instructions: instructions.md  # file, relative to the lab dir
    seed_spec:                     # or `seed`; dict, passed verbatim
      lan_octet: {type: int, min: 2, max: 9}
    limits:                        # dict, passed verbatim
      time_minutes: 45
      ready_wait_seconds: 120
      pass_threshold: 0.7          # optional; default 0.7
    checks:                        # list of check dicts, stored verbatim
      - {id: c1, type: probe, node: client, weight: 1, probe: ping}

``instructions.md`` may contain ``$include: <manual-file>#<anchor>`` directive
lines; each is replaced by the slice of the referenced chapter markdown around
the heading whose slug matches ``<anchor>`` (resolved against ``chapters_dir``).
Unresolvable includes degrade gracefully (whole file, or a neutral note) rather
than crashing.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import markdown as md
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Activity
from app.models.lab import LabTemplate

_DEFAULT_PASS_THRESHOLD = 0.7

# A standalone `$include: file.md#anchor` directive line.
_INCLUDE = re.compile(r"^[ \t]*\$include:[ \t]*(?P<file>[^#\s]+)(?:#(?P<anchor>\S+))?[ \t]*$")
# A markdown ATX heading: capture level (#count) and text.
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.*?)[ \t]*#*$")


@dataclass
class LabSpec:
    """Parsed, file-resolved representation of a single lab directory."""

    slug: str
    title: str
    chapter_number: int | None
    topology_text: str
    instructions_md: str
    checks: list = field(default_factory=list)
    seed_spec: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _slice_chapter(chapter_md: str, anchor: str) -> str | None:
    """Return the markdown from the heading whose slug==anchor up to the next
    heading of equal-or-higher level. ``None`` if no heading matches."""
    lines = chapter_md.splitlines()
    start = None
    start_level = 0
    for i, line in enumerate(lines):
        m = _HEADING.match(line)
        if not m:
            continue
        level = len(m.group(1))
        if start is None:
            if _slugify(m.group(2)) == anchor.lower():
                start = i
                start_level = level
        elif level <= start_level:
            return "\n".join(lines[start:i]).strip()
    if start is None:
        return None
    return "\n".join(lines[start:]).strip()


def _resolve_include(match: re.Match, chapters_dir: Path | None) -> str:
    file_name = match.group("file")
    anchor = match.group("anchor")
    if chapters_dir is None:
        return f"<!-- include {file_name} unavailable (no chapters dir) -->"
    src = Path(chapters_dir) / file_name
    if not src.is_file():
        return f"<!-- include {file_name} not found -->"
    text = src.read_text(encoding="utf-8")
    if anchor:
        sliced = _slice_chapter(text, anchor)
        if sliced is not None:
            return sliced
    # No anchor, or anchor not found: fall back to the whole referenced file.
    return text.strip()


def _resolve_includes(instructions_md: str, chapters_dir: Path | None) -> str:
    out: list[str] = []
    for line in instructions_md.splitlines():
        m = _INCLUDE.match(line)
        if m:
            out.append(_resolve_include(m, chapters_dir))
        else:
            out.append(line)
    return "\n".join(out)


def parse_lab(dir_path, chapters_dir=None) -> LabSpec:
    """Parse a lab directory (``lab.yaml`` + referenced files) into a LabSpec.

    Args:
        dir_path: The lab directory containing ``lab.yaml``.
        chapters_dir: Optional directory used to resolve ``$include:`` directives
            in the instructions markdown.
    """
    dir_path = Path(dir_path)
    data = yaml.safe_load((dir_path / "lab.yaml").read_text(encoding="utf-8")) or {}
    if "lab" in data and isinstance(data["lab"], dict):
        data = data["lab"]

    slug = str(data.get("slug") or data.get("id") or "")
    title = str(data.get("title", ""))

    chapter_raw = data.get("chapter_number", data.get("chapter_ref"))
    chapter_number = int(chapter_raw) if chapter_raw is not None else None

    topo_file = str(data.get("topology", "topo.clab.yml"))
    topology_text = (dir_path / topo_file).read_text(encoding="utf-8")

    instr_file = str(data.get("instructions", "instructions.md"))
    instructions_md = (dir_path / instr_file).read_text(encoding="utf-8")
    instructions_md = _resolve_includes(instructions_md, chapters_dir)

    checks = list(data.get("checks", []) or [])
    seed_spec = dict(data.get("seed_spec", data.get("seed", {})) or {})
    limits = dict(data.get("limits", {}) or {})

    return LabSpec(
        slug=slug,
        title=title,
        chapter_number=chapter_number,
        topology_text=topology_text,
        instructions_md=instructions_md,
        checks=checks,
        seed_spec=seed_spec,
        limits=limits,
    )


def _source_hash(spec: LabSpec, instructions_html: str) -> str:
    payload = json.dumps(
        {
            "slug": spec.slug,
            "title": spec.title,
            "chapter_number": spec.chapter_number,
            "topology": spec.topology_text,
            "instructions_html": instructions_html,
            "checks": spec.checks,
            "seed_spec": spec.seed_spec,
            "limits": spec.limits,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def import_labs(db: Session, *, tenant_id, course_id, labs_dir, chapters_dir=None) -> list[LabTemplate]:
    """Upsert all labs under ``labs_dir`` for a course.

    For each ``<labs_dir>/*/lab.yaml``: parse, render instructions to HTML,
    compute a ``source_hash`` over the source, and upsert a paired
    ``Activity(type="lab")`` + :class:`LabTemplate`, keyed by (course_id, slug).
    Idempotent: unchanged labs are skipped; ``version`` is bumped only when the
    ``source_hash`` changes. Does not commit.
    """
    templates: list[LabTemplate] = []

    for lab_yaml in sorted(Path(labs_dir).glob("*/lab.yaml")):
        spec = parse_lab(lab_yaml.parent, chapters_dir=chapters_dir)
        if not spec.slug:
            continue

        instructions_html = md.markdown(
            spec.instructions_md, extensions=["tables", "fenced_code"]
        )
        source_hash = _source_hash(spec, instructions_html)
        pass_threshold = float(spec.limits.get("pass_threshold", _DEFAULT_PASS_THRESHOLD))

        template = db.scalars(
            select(LabTemplate)
            .where(LabTemplate.tenant_id == tenant_id)
            .where(LabTemplate.course_id == course_id)
            .where(LabTemplate.slug == spec.slug)
        ).first()

        if template is None:
            activity = Activity(
                tenant_id=tenant_id,
                course_id=course_id,
                chapter_number=spec.chapter_number,
                type="lab",
                bank_id=None,
                title=spec.title,
                pass_threshold=pass_threshold,
            )
            db.add(activity)
            db.flush()
            template = LabTemplate(
                tenant_id=tenant_id,
                course_id=course_id,
                chapter_number=spec.chapter_number,
                activity_id=activity.id,
                slug=spec.slug,
                title=spec.title,
                topology=spec.topology_text,
                instructions_html=instructions_html,
                checks=spec.checks,
                seed_spec=spec.seed_spec,
                limits=spec.limits,
                source_hash=source_hash,
                version=1,
            )
            db.add(template)
        elif template.source_hash != source_hash:
            existing = db.scalars(
                select(Activity)
                .where(Activity.tenant_id == tenant_id)
                .where(Activity.id == template.activity_id)
            ).first()
            if existing is not None:
                existing.title = spec.title
                existing.chapter_number = spec.chapter_number
                existing.pass_threshold = pass_threshold
            template.chapter_number = spec.chapter_number
            template.title = spec.title
            template.topology = spec.topology_text
            template.instructions_html = instructions_html
            template.checks = spec.checks
            template.seed_spec = spec.seed_spec
            template.limits = spec.limits
            template.source_hash = source_hash
            template.version += 1
        # else: unchanged — skip

        templates.append(template)

    db.flush()
    return templates
