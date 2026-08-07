"""The exam engine — one owner for what an exam *is*.

Before this module the answer depended on who was asking. A learner sitting a
course activity and an applicant sitting the entrance exam shared exactly one
function, ``grade_submission``; selection, option order, validity and result
policy were each implemented once, on whichever side happened to need them
first. Two consequences were live defects rather than asymmetries: course
learners saw an identical option order, so "the answer is the third one"
transferred between them, and a course sitting had no validity gate, so a
forty-second final at chance was recorded as a genuine result.

See ``docs/adr/0005-assessment-engine-owns-exam-logic.md``.

What lives here
---------------
The *decisions*: who may sit, which questions they get, in what order they see
them, whether the sitting counts as signal. Grading stays in ``grading`` as a
pure function; this module calls it rather than reimplementing it.

What does not live here
-----------------------
The *facts* — questions, options, answers, competency tags — which belong to
the banks, and persistence, which belongs to the adapters that know whether
they are writing against a ``Person`` or an ``Applicant``.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Any, Protocol

# A sitting at or below this fraction is indistinguishable from clicking at
# random on a four-option paper, and one faster than this was not engaged with.
# Neither is a weak candidate; both are an ABSENCE OF DATA, and scoring them as
# genuine low results pollutes whatever ranking or gradebook consumes them.
MIN_VALID_FRACTION = 1.0 / 3.0
MIN_DURATION_SECONDS = 6 * 60

INVALID_NEAR_CHANCE = "near_chance"
INVALID_TOO_FAST = "too_fast"


class Sitter(Protocol):
    """Whoever is taking the exam.

    Deliberately narrow: the engine needs an identity to make its per-sitter
    decisions reproducible, and nothing else. A ``Person`` and an ``Applicant``
    both satisfy this, which is the point — the identity split between admitted
    learners and candidates is an admissions concern, not an exam one.
    """

    id: Any


class Question(Protocol):
    """The shape the engine needs from a question. Banks own the rest."""

    ext_id: str
    category: Any
    options: Any


@dataclass(frozen=True)
class SelectionPolicy:
    """How many questions to draw, and how.

    ``per_category`` draws that many from each competency, so every sitter is
    measured on the same shape and their per-domain profiles stay comparable —
    a flat draw would hand one sitter nine numeracy items and another two.

    ``total`` draws that many across the bank, ignoring competency.

    Both zero means the whole bank, which is the behaviour that existed before
    any pooling and remains the default.
    """

    per_category: int = 0
    total: int = 0

    def __post_init__(self) -> None:
        if self.per_category and self.total:
            raise ValueError("choose per_category or total, not both")


def _rank(sitter: Sitter, salt: str, key: str) -> str:
    """A stable pseudo-random ordering key for (sitter, thing).

    Deterministic so a reload or a resumed sitting reproduces the same paper,
    and so grading can rebuild what was shown without persisting it. Salted so
    that selection order and presentation order are independent — otherwise the
    first questions drawn would also be the ones whose options moved least.
    """
    return hashlib.sha256(f"{sitter.id}:{salt}{key}".encode()).hexdigest()


def select(sitter: Sitter, questions: list, policy: SelectionPolicy) -> list:
    """The questions this sitter gets, in the order they get them."""
    if policy.per_category:
        by_category: dict[str, list] = {}
        for q in questions:
            by_category.setdefault(getattr(q, "category", None) or "general", []).append(q)

        chosen: list = []
        for group in by_category.values():
            if len(group) <= policy.per_category:
                # A category smaller than the draw contributes all of itself
                # rather than vanishing from the profile.
                chosen.extend(group)
                continue
            ranked = sorted(group, key=lambda q: _rank(sitter, "", q.ext_id))
            chosen.extend(ranked[: policy.per_category])
    elif policy.total:
        ranked = sorted(questions, key=lambda q: _rank(sitter, "", q.ext_id))
        chosen = ranked[: policy.total]
    else:
        chosen = list(questions)

    # Re-rank the whole paper so it is not grouped by competency, which would
    # telegraph the structure and let sitters compare notes by section.
    chosen.sort(key=lambda q: _rank(sitter, "order:", q.ext_id))
    return chosen


def present_options(sitter: Sitter, question: Question) -> list[str]:
    """This question's options in a per-sitter order.

    A fixed order leaks: sitters talk, and "the answer is C" stays true for
    everyone. Deterministic in (sitter, question) so a reload does not move the
    options under autosaved answers. Safe because answers are submitted by
    option TEXT, so grading is order-independent.
    """
    opts = list(getattr(question, "options", None) or [])
    rng = random.Random(_rank(sitter, "", question.ext_id))
    rng.shuffle(opts)
    return opts


def check_validity(fraction: float, duration_seconds: float | None) -> tuple[bool, str | None]:
    """Is this sitting real signal, or an absence of data?"""
    if fraction <= MIN_VALID_FRACTION + 1e-9:
        return False, INVALID_NEAR_CHANCE
    if duration_seconds is None or duration_seconds < MIN_DURATION_SECONDS:
        return False, INVALID_TOO_FAST
    return True, None
