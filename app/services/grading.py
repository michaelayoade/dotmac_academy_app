from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class GradeResult:
    score: float; max_score: float; fraction: float; passed: bool; per_item: list[dict]


def _grade_numeric(chosen: list, correct: list, opts) -> bool:
    if not chosen:
        return False
    try:
        got = float(chosen[0])
    except (ValueError, TypeError):
        return False
    if isinstance(opts, dict) and "tolerance" in opts:           # gaps: tolerance mode
        try:
            tol = float(opts.get("tolerance", 0))
        except (ValueError, TypeError):
            tol = 0.0
        try:
            target = float(correct[0])
        except (ValueError, TypeError, IndexError):
            return False
        return abs(got - target) <= tol
    try:                                                          # buildout: exact-or-range
        bounds = [float(x) for x in correct]
    except (ValueError, TypeError):
        return False
    if not bounds:
        return False
    if len(bounds) == 1:
        return got == bounds[0]
    lo, hi = min(bounds[0], bounds[1]), max(bounds[0], bounds[1])
    return lo <= got <= hi


def _norm_text(s) -> str:
    return re.sub(r"\s+", " ", str(s).strip().lower())


def _grade_short_text(chosen: list, correct: list, opts) -> bool:
    if not chosen or not str(chosen[0]).strip():
        return False
    if isinstance(opts, dict) and opts.get("regex"):             # gaps: regex mode
        for pattern in correct:
            try:
                if re.fullmatch(str(pattern), str(chosen[0]).strip(), re.IGNORECASE):
                    return True
            except re.error:
                pass
        return False
    target = _norm_text(chosen[0])                               # buildout: normalized
    return target in {_norm_text(e) for e in correct}


def _is_correct(qtype: str, chosen: list, expected: list, opts=None) -> bool:
    if qtype == "numeric":
        return _grade_numeric(chosen, expected, opts)
    if qtype == "short_text":
        return _grade_short_text(chosen, expected, opts)
    return set(chosen) == set(expected)


def grade_submission(answers: dict[str, list], questions: list[dict], pass_threshold: float) -> GradeResult:
    score = 0.0; max_score = 0.0; per_item = []
    for q in questions:
        w = float(q.get("weight", 1)); max_score += w
        chosen = list(answers.get(q["ext_id"], []))
        raw_correct = q.get("correct", [])
        # Authors may store `correct` as a scalar (e.g. numeric 42) or a list; normalize.
        expected = list(raw_correct) if isinstance(raw_correct, list) else [raw_correct]
        opts = q.get("options") or {}
        ok = _is_correct(q.get("type", "single"), chosen, expected, opts)
        if ok:
            score += w
        per_item.append({"id": q["ext_id"], "correct": ok, "chosen": chosen,
                         "expected": expected, "weight": q.get("weight", 1)})
    fraction = (score / max_score) if max_score else 0.0
    return GradeResult(score=score, max_score=max_score, fraction=fraction,
                       passed=(max_score > 0 and fraction >= pass_threshold), per_item=per_item)
