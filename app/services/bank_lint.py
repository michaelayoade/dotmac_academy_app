"""The question-bank rules, with no database and no application imports.

Split out of ``bank_loader`` so the rules can run where the content lives. The
linter is in this repository; 252 of the technical banks are in
``dotmac-academy``, which had no CI at all — so the only banks ever checked
were the ones that happened to sit beside the checker. That is why 246 of 333
banks in the live estate were failing while the 82 in this repo were clean:
same authors, same care, and a machine looking at one set and not the other.

This module imports nothing but ``yaml`` and the standard library, so the other
repository can run it directly:

    python -m app.services.bank_lint path/to/banks/*.yaml

``bank_loader`` re-exports everything here, so existing callers are unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_TARGET = {"recall": 0.20, "application": 0.50, "analysis": 0.30}
_TOL = 0.10

# Distractor-balance thresholds. A bank fails these when the correct option is
# identifiable by its shape rather than its content — the standard authoring
# failure where the answer is written as the careful full sentence and the
# distractors as short dismissals. A learner can then score well by picking the
# longest option without reading the course, so the bank measures nothing.
# The check is symmetric: an answer that is reliably the *shortest* option is
# just as easy to spot as one that is reliably the longest, and authors fixing
# the second failure routinely create the first.
_MIN_BALANCE_SAMPLE = 5  # below this, one question swings the share too far
_MAX_EXTREME_SHARE = 0.40  # chance is 0.25 for 4-option questions
_MAX_LENGTH_RATIO = 1.30  # mean correct length over mean distractor length


_ASSESSMENT_MODES = {"practice", "graded", "exam"}


@dataclass
class BankDoc:
    course: str
    chapter: int | None
    kind: str
    version: int
    questions: list[dict]
    # Optional assessment policy declared alongside the questions. Absent keys
    # leave the Activity's existing value alone, so adding a policy to one bank
    # never disturbs content that has not declared one. Defaulted so that every
    # existing BankDoc(...) construction keeps working.
    policy: dict = field(default_factory=dict)


def parse_bank(path) -> BankDoc:
    """Load and parse a bank YAML file into a BankDoc dataclass."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))["bank"]
    return BankDoc(
        course=data["course"],
        chapter=data.get("chapter"),
        kind=data["kind"],
        version=int(data.get("version", 1)),
        questions=list(data["questions"]),
        policy=dict(data.get("policy") or {}),
    )


def _policy_violations(doc: BankDoc) -> list[str]:
    """Validate a declared assessment policy against the bank it applies to."""
    out: list[str] = []
    policy = doc.policy
    unknown = set(policy) - {"pool", "max_attempts", "mode", "pass_threshold"}
    if unknown:
        out.append(f"policy: unknown key(s) {', '.join(sorted(unknown))}")

    pool = policy.get("pool")
    if pool is not None:
        if not isinstance(pool, int) or pool < 1:
            out.append(f"policy: pool must be a positive integer, got {pool!r}")
        elif pool > len(doc.questions):
            # A pool at or above the bank size draws every question every time,
            # which is the behaviour the author was trying to move away from.
            out.append(
                f"policy: pool {pool} exceeds the {len(doc.questions)} questions in "
                f"the bank — nothing is held back"
            )

    attempts = policy.get("max_attempts")
    if attempts is not None and (not isinstance(attempts, int) or attempts < 1):
        out.append(f"policy: max_attempts must be a positive integer, got {attempts!r}")

    threshold = policy.get("pass_threshold")
    if threshold is not None:
        if not isinstance(threshold, int | float) or isinstance(threshold, bool):
            out.append(f"policy: pass_threshold must be a number, got {threshold!r}")
        elif not 0.0 <= float(threshold) <= 1.0:
            out.append(
                f"policy: pass_threshold is a fraction between 0 and 1, got {threshold!r}"
            )

    mode = policy.get("mode")
    if mode is not None and mode not in _ASSESSMENT_MODES:
        out.append(
            f"policy: mode must be one of {', '.join(sorted(_ASSESSMENT_MODES))}, "
            f"got {mode!r}"
        )

    return out


def _competency_of(q: dict) -> str | None:
    """The skill domain a question measures, under either spelling.

    The entrance bank tags `category:`; the 252 technical manual banks tag
    `competency:` and meant the same thing. Only `category` was ever read, so
    every technical question imported with a NULL domain and the taxonomy the
    content team maintained was discarded at the door — which also left those
    banks outside the per-domain balance check below.
    """
    value = q.get("category") or q.get("competency")
    return str(value) if value else None


def _balance_stats(
    questions: list[dict],
) -> tuple[int, list[str], list[str], list[float]]:
    """Return (sample, uniquely-longest ids, uniquely-shortest ids, length ratios).

    Only questions carrying a real option list participate; ``numeric`` and
    ``short_text`` items have nothing to compare and ``truefalse`` items have
    fixed-length options. The extreme-length tests apply to single-answer
    questions only — a ``multi`` question with three correct options holds both
    the longest and the shortest string by construction.
    """
    sample = 0
    longest_ids: list[str] = []
    shortest_ids: list[str] = []
    ratios: list[float] = []

    for q in questions:
        opts = q.get("options")
        correct = q.get("correct")
        if q.get("type") == "truefalse":
            # Fixed "true"/"false" options: the one-character difference between
            # them is not a signal an author can balance away.
            continue
        if not isinstance(opts, list) or len(opts) < 2:
            continue
        if not isinstance(correct, list) or not correct:
            continue
        chosen = [o for o in opts if o in correct]
        distractors = [o for o in opts if o not in correct]
        if not chosen or not distractors:
            continue

        sample += 1
        mean_correct = sum(len(str(o)) for o in chosen) / len(chosen)
        mean_distractor = sum(len(str(o)) for o in distractors) / len(distractors)
        if mean_distractor:
            ratios.append(mean_correct / mean_distractor)

        if q.get("type") == "multi":
            continue
        lengths = [len(str(o)) for o in opts]
        answer = len(str(chosen[0]))
        qid = str(q.get("id"))
        # A tie leaks no signal — only a strictly extreme option does.
        if lengths.count(max(lengths)) == 1 and answer == max(lengths):
            longest_ids.append(qid)
        if lengths.count(min(lengths)) == 1 and answer == min(lengths):
            shortest_ids.append(qid)

    return sample, longest_ids, shortest_ids, ratios


def _distractor_balance_violations(questions: list[dict], scope: str = "") -> list[str]:
    """Flag banks whose correct options are identifiable by length alone.

    ``scope`` labels a subset (a competency category) so the message says where
    the imbalance is.
    """
    sample, longest_ids, shortest_ids, ratios = _balance_stats(questions)
    if sample < _MIN_BALANCE_SAMPLE:
        return []

    where = f"{scope}: " if scope else ""
    out: list[str] = []
    for label, ids in (("longest", longest_ids), ("shortest", shortest_ids)):
        share = len(ids) / sample
        if share > _MAX_EXTREME_SHARE:
            shown = ", ".join(ids[:8])
            more = f" (+{len(ids) - 8} more)" if len(ids) > 8 else ""
            out.append(
                f"{where}distractor balance: correct answer is the {label} option in "
                f"{len(ids)}/{sample} questions ({share:.0%}, max "
                f"{_MAX_EXTREME_SHARE:.0%}) — {shown}{more}"
            )

    if ratios:
        mean_ratio = sum(ratios) / len(ratios)
        if not 1 / _MAX_LENGTH_RATIO <= mean_ratio <= _MAX_LENGTH_RATIO:
            direction = "longer" if mean_ratio > 1 else "shorter"
            out.append(
                f"{where}distractor balance: correct options average {mean_ratio:.2f}x "
                f"the length of their distractors — consistently {direction} "
                f"(allowed {1 / _MAX_LENGTH_RATIO:.2f}x to {_MAX_LENGTH_RATIO:.2f}x)"
            )

    return out


def lint_bank(doc: BankDoc) -> list[str]:
    """Validate a BankDoc against rubric-mix and correct-in-options rules.

    Returns a (possibly empty) list of human-readable violation strings.
    An empty list means the bank is clean.

    Rules:
    - Bank must not be empty.
    - Each question must have a valid rubric_category (recall/application/analysis).
    - For non-truefalse questions, every entry in `correct` must appear in `options`.
    - The overall rubric mix must be 20% recall / 50% application / 30% analysis
      within ±10 percentage points.
    - Distractors must be balanced against the correct option: the answer may be
      the strictly longest — or strictly shortest — option in at most 40% of
      single-answer questions, and correct options must average between 0.77x
      and 1.30x their distractors' length.
    - A declared `policy` block must use known keys and sane values, and a
      question pool must actually hold something back.
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
        qtype = q.get("type")
        if qtype == "numeric":
            try:
                float(q.get("correct", ""))
            except (ValueError, TypeError):
                out.append(f"{q.get('id')}: numeric correct must be a parseable number")
        elif qtype == "short_text":
            accepted = q.get("correct", [])
            if not isinstance(accepted, list) or len(accepted) == 0:
                out.append(f"{q.get('id')}: short_text correct must be a non-empty list")
        elif qtype != "truefalse":
            raw_opts = q.get("options", [])
            # An option that is not a string means the YAML parsed it as
            # something else — most often text of the form "Word: rest", which
            # becomes a mapping. Report it; do not raise on the way past.
            malformed = [o for o in raw_opts if not isinstance(o, str)]
            if malformed:
                out.append(
                    f"{q.get('id')}: option is not text — {malformed[0]!r}. Text "
                    f"beginning 'Word: ' parses as a YAML mapping; quote it or reword."
                )
                continue
            opts = set(raw_opts)
            for c in q.get("correct", []):
                if c not in opts:
                    out.append(f"{q.get('id')}: correct {c!r} not in options")

    for cat, target in _TARGET.items():
        frac = counts[cat] / n
        # +1e-9 epsilon: a mix exactly at the tolerance edge (e.g. analysis 40%
        # vs target 30% ±10%) must pass — bare float subtraction yields
        # 0.4-0.3==0.10000000000000003 and would wrongly reject a compliant bank.
        if abs(frac - target) > _TOL + 1e-9:
            out.append(
                f"rubric mix off: {cat} {frac:.0%} (target {target:.0%} ±{_TOL:.0%})"
            )

    out.extend(_distractor_balance_violations(doc.questions))

    # Where questions carry a competency `category`, that category is a scoring
    # unit in its own right — the entrance exam reports a per-category profile
    # and draws per category. A bank can therefore look balanced overall while
    # one competency is entirely guessable, which is the case that matters most:
    # a candidate's safety score is not rescued by well-written numeracy items.
    categories: dict[str, list[dict]] = {}
    for q in doc.questions:
        category = _competency_of(q)
        if category:
            categories.setdefault(category, []).append(q)
    if len(categories) > 1:
        for category, group in sorted(categories.items()):
            out.extend(_distractor_balance_violations(group, scope=category))

    out.extend(_policy_violations(doc))

    return out


def _main(argv: list[str]) -> int:
    """Lint bank files given as paths. Exit 1 if any fails, so CI can gate on it."""
    import sys

    paths: list[Path] = []
    for a in argv:
        p = Path(a)
        paths.extend(sorted(p.glob("**/*.yaml")) if p.is_dir() else [p])
    if not paths:
        print("no bank files given", file=sys.stderr)
        return 2

    failed = 0
    for path in paths:
        try:
            violations = lint_bank(parse_bank(path))
        except Exception as exc:  # unparseable is a failure, not a crash
            print(f"FAIL {path}: could not parse — {exc}")
            failed += 1
            continue
        if violations:
            failed += 1
            print(f"FAIL {path}")
            for v in violations:
                print(f"     {v}")
    print(f"\n{len(paths) - failed}/{len(paths)} bank(s) pass")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))
