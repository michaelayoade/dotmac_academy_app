from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class GradeResult:
    score: float; max_score: float; fraction: float; passed: bool; per_item: list[dict]


def _norm_text(s: str) -> str:
    """Lowercase, strip, and collapse internal whitespace for text matching."""
    return re.sub(r"\s+", " ", str(s).strip().lower())


def _grade_numeric(chosen: list, expected: list) -> bool:
    """numeric: expected = [value] for exact, or [min, max] for an inclusive range."""
    if not chosen or not expected:
        return False
    try:
        got = float(chosen[0])
        bounds = [float(x) for x in expected]
    except (ValueError, TypeError):
        return False
    if len(bounds) == 1:
        return got == bounds[0]
    lo, hi = min(bounds[0], bounds[1]), max(bounds[0], bounds[1])
    return lo <= got <= hi


def _grade_short_text(chosen: list, expected: list) -> bool:
    """short_text: case/whitespace-insensitive match against any accepted answer."""
    if not chosen:
        return False
    return _norm_text(chosen[0]) in {_norm_text(e) for e in expected}


def _is_correct(qtype: str, chosen: list, expected: list) -> bool:
    if qtype == "numeric":
        return _grade_numeric(chosen, expected)
    if qtype == "short_text":
        return _grade_short_text(chosen, expected)
    # single | multi | truefalse (and any unknown type): exact set match.
    return set(chosen) == set(expected)


def grade_submission(answers: dict[str, list], questions: list[dict], pass_threshold: float) -> GradeResult:
    score = 0.0; max_score = 0.0; per_item = []
    for q in questions:
        w = float(q.get("weight", 1)); max_score += w
        chosen = list(answers.get(q["ext_id"], []))
        expected = list(q.get("correct", []))
        ok = _is_correct(q.get("type", "single"), chosen, expected)
        if ok:
            score += w
        per_item.append({"id": q["ext_id"], "correct": ok, "chosen": chosen,
                         "expected": expected, "weight": q.get("weight", 1)})
    fraction = (score / max_score) if max_score else 0.0
    return GradeResult(score=score, max_score=max_score, fraction=fraction,
                       passed=(max_score > 0 and fraction >= pass_threshold), per_item=per_item)
