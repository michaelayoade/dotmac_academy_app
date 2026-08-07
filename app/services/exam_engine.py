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

# A sitting near the guessing baseline, or faster than anyone could read the
# paper, is not a weak candidate — it is an ABSENCE OF DATA, and scoring it as
# a genuine low result pollutes whatever ranking or gradebook consumes it.
#
# Both floors are DERIVED from the paper rather than fixed, because both depend
# on it. The old constants encoded "four options" and "30 questions" in their
# comments and then stopped tracking either: once the entrance paper size became
# configurable, a 60-question sitting was still gated at six minutes. A setting
# would not have fixed that — it would only have added a second value to drift.
SECONDS_PER_QUESTION = 12.0  # faster than this is not reading the question
NEAR_CHANCE_MARGIN = 1.33  # the gate sits this far above the paper's own chance

# Fallbacks for callers that cannot supply the paper. They encode the historical
# assumption — 30 four-option questions — and are what those callers already got.
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

    # A read-only property rather than an attribute, so both a mutable ORM
    # model and a frozen dataclass adapter satisfy it.
    @property
    def id(self) -> Any: ...


class Question(Protocol):
    """The shape the engine needs from a question. Banks own the rest."""

    @property
    def ext_id(self) -> str: ...

    @property
    def category(self) -> Any: ...

    @property
    def options(self) -> Any: ...


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


def select(
    sitter: Sitter, questions: list, policy: SelectionPolicy, variant: str = ""
) -> list:
    """The questions this sitter gets, in the order they get them.

    ``variant`` distinguishes repeat sittings by the same person. Without it a
    learner's second attempt at a pooled activity would draw the identical
    paper as their first, which removes the only reason to pool a bank that
    allows retakes. The entrance exam is a single sitting and passes nothing.
    """
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
            ranked = sorted(group, key=lambda q: _rank(sitter, variant, q.ext_id))
            chosen.extend(ranked[: policy.per_category])
    elif policy.total:
        ranked = sorted(questions, key=lambda q: _rank(sitter, variant, q.ext_id))
        chosen = ranked[: policy.total]
    else:
        chosen = list(questions)

    # Re-rank the whole paper so it is not grouped by competency, which would
    # telegraph the structure and let sitters compare notes by section.
    chosen.sort(key=lambda q: _rank(sitter, f"{variant}order:", q.ext_id))
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


def chance_baseline(questions: list) -> float:
    """The score guessing would produce on *this* paper.

    Averaged over the questions that actually offer options, so a paper with
    true/false items reports the ~50% it really carries rather than the 25% a
    four-option assumption would claim.
    """
    per_question = []
    for q in questions:
        opts = getattr(q, "options", None)
        if isinstance(opts, list) and len(opts) >= 2:
            per_question.append(1.0 / len(opts))
    if not per_question:
        return MIN_VALID_FRACTION / NEAR_CHANCE_MARGIN
    return sum(per_question) / len(per_question)


def near_chance_floor(questions: list) -> float:
    """Scores at or below this are indistinguishable from guessing."""
    return chance_baseline(questions) * NEAR_CHANCE_MARGIN


def duration_floor(questions: list) -> float:
    """The fastest a sitting could plausibly have been read."""
    return len(questions) * SECONDS_PER_QUESTION


def check_validity(
    fraction: float,
    duration_seconds: float | None,
    *,
    questions: list | None = None,
) -> tuple[bool, str | None]:
    """Is this sitting real signal, or an absence of data?

    Pass ``questions`` — the paper actually served — and both floors follow from
    it. Without them the historical constants apply, which is what every caller
    got before the floors were derived.
    """
    score_floor = near_chance_floor(questions) if questions else MIN_VALID_FRACTION
    time_floor = duration_floor(questions) if questions else MIN_DURATION_SECONDS

    if fraction <= score_floor + 1e-9:
        return False, INVALID_NEAR_CHANCE
    if duration_seconds is None or duration_seconds < time_floor:
        return False, INVALID_TOO_FAST
    return True, None
