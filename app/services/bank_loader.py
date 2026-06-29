"""Question-bank loader: parse, lint, and persist YAML MCQ banks.

Usage
-----
    from app.services.bank_loader import parse_bank, lint_bank, load_bank

    doc = parse_bank("/path/to/banks/foundation-ch3.yaml")
    violations = lint_bank(doc)
    if violations:
        for v in violations:
            print(v)
    else:
        bank = load_bank(db, tenant_id=tid, course_id=cid, doc=doc)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Question, QuestionBank

_TARGET = {"recall": 0.20, "application": 0.50, "analysis": 0.30}
_TOL = 0.10
_OPTION_TYPES = {"single", "multi"}


@dataclass
class BankDoc:
    course: str
    chapter: int | None
    kind: str
    version: int
    questions: list[dict]


def parse_bank(path) -> BankDoc:
    """Load and parse a bank YAML file into a BankDoc dataclass."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))["bank"]
    return BankDoc(
        course=data["course"],
        chapter=data.get("chapter"),
        kind=data["kind"],
        version=int(data.get("version", 1)),
        questions=list(data["questions"]),
    )


def lint_bank(doc: BankDoc) -> list[str]:
    """Validate a BankDoc against rubric-mix and correct-in-options rules.

    Returns a (possibly empty) list of human-readable violation strings.
    An empty list means the bank is clean.

    Rules:
    - Bank must not be empty.
    - Each question must have a valid rubric_category (recall/application/analysis).
    - For single/multi questions, every entry in `correct` must appear in `options`.
    - The overall rubric mix must be 20% recall / 50% application / 30% analysis
      within ±10 percentage points.
    """
    out: list[str] = []
    n = len(doc.questions)
    if n == 0:
        return ["bank has no questions"]

    counts: dict[str, int] = {k: 0 for k in _TARGET}

    for q in doc.questions:
        cat = q.get("rubric_category")
        if cat not in _TARGET:
            out.append(f"{q.get('id')}: invalid rubric_category {cat!r}")
            continue
        counts[cat] += 1
        if q.get("type") in _OPTION_TYPES:
            opts = set(q.get("options", []))
            for c in q.get("correct", []):
                if c not in opts:
                    out.append(f"{q.get('id')}: correct {c!r} not in options")

    for cat, target in _TARGET.items():
        frac = counts[cat] / n
        if abs(frac - target) > _TOL:
            out.append(
                f"rubric mix off: {cat} {frac:.0%} (target {target:.0%} ±{_TOL:.0%})"
            )

    return out


def load_bank(db: Session, *, tenant_id, course_id, doc: BankDoc) -> QuestionBank:
    """Upsert a QuestionBank and replace its Questions from a BankDoc.

    Finds an existing bank by (tenant_id, course_id, chapter_number, kind).
    If it exists, deletes all its existing Questions first (replace semantics).
    Creates new Question rows from doc.questions.
    Returns the QuestionBank ORM instance (not yet committed).
    """
    bank = db.scalars(
        select(QuestionBank)
        .where(QuestionBank.tenant_id == tenant_id)
        .where(QuestionBank.course_id == course_id)
        .where(QuestionBank.chapter_number == doc.chapter)
        .where(QuestionBank.kind == doc.kind)
    ).first()

    if bank is None:
        bank = QuestionBank(
            tenant_id=tenant_id,
            course_id=course_id,
            chapter_number=doc.chapter,
            kind=doc.kind,
            version=doc.version,
        )
        db.add(bank)
        db.flush()
    else:
        db.query(Question).filter(Question.bank_id == bank.id).delete()
        bank.version = doc.version

    for q in doc.questions:
        db.add(
            Question(
                tenant_id=tenant_id,
                bank_id=bank.id,
                ext_id=q["id"],
                stem=q["stem"],
                type=q["type"],
                options=q.get("options", []),
                correct=q.get("correct", []),
                rubric_category=q["rubric_category"],
                explanation=q.get("explanation", ""),
                weight=int(q.get("weight", 1)),
            )
        )

    db.flush()
    return bank
