"""Loading question banks into the database.

The *rules* live in :mod:`app.services.bank_lint`, which has no database or
application imports so the content repository can run them in its own CI.
Everything from there is re-exported here, so existing callers are unchanged.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Question, QuestionBank
from app.services.bank_lint import (  # noqa: F401 — re-exported for existing callers
    BankDoc,
    _competency_of,
    lint_bank,
    parse_bank,
)


def doc_from_db(db: Session, *, bank: QuestionBank, course_slug: str) -> BankDoc:
    """Rebuild a BankDoc from a bank already in the database.

    So the live estate can be checked with :func:`lint_bank` itself rather than
    a second implementation of the rules in SQL. Two implementations of the same
    decision drift the moment a threshold moves; this keeps one.
    """
    rows = db.scalars(
        select(Question)
        .where(Question.tenant_id == bank.tenant_id)
        .where(Question.bank_id == bank.id)
        .order_by(Question.ext_id)
    ).all()
    return BankDoc(
        course=course_slug,
        chapter=bank.chapter_number,
        kind=bank.kind,
        version=bank.version,
        questions=[
            {
                "id": q.ext_id,
                "stem": q.stem,
                "type": q.type,
                "options": q.options,
                "correct": q.correct,
                "rubric_category": q.rubric_category,
                "category": q.category,
                "explanation": q.explanation,
                "weight": q.weight,
            }
            for q in rows
        ],
        # Policy lives on the Activity once loaded, not on the bank, so a
        # database-sourced doc carries none — and lint_bank skips an empty one.
        policy={},
    )


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
                category=_competency_of(q),
                explanation=q.get("explanation", ""),
                weight=int(q.get("weight", 1)),
            )
        )

    db.flush()
    return bank
