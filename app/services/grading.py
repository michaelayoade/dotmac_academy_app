from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class GradeResult:
    score: float; max_score: float; fraction: float; passed: bool; per_item: list[dict]


def _grade_numeric(chosen: list[str], raw_correct: Any, opts: Any) -> tuple[bool, list]:
    raw = chosen[0] if chosen else ""
    try:
        val = float(raw)
    except (ValueError, TypeError):
        return False, [raw_correct]
    try:
        target_raw = raw_correct[0] if isinstance(raw_correct, list) else raw_correct
        target = float(target_raw)
    except (ValueError, TypeError, IndexError):
        return False, [raw_correct]
    try:
        tolerance = float(opts.get("tolerance", 0)) if isinstance(opts, dict) else 0.0
    except (TypeError, ValueError):
        # Malformed author-supplied tolerance must not 500 the learner's submit.
        tolerance = 0.0
    return abs(val - target) <= tolerance, [target]


def _grade_short_text(chosen: list[str], accepted: list, opts: Any) -> bool:
    raw = chosen[0].strip() if chosen and chosen[0] else ""
    if not raw:
        return False
    use_regex = isinstance(opts, dict) and bool(opts.get("regex", False))
    for pattern in accepted:
        if use_regex:
            try:
                if re.fullmatch(str(pattern), raw, re.IGNORECASE):
                    return True
            except re.error:
                pass
        else:
            if raw.lower() == str(pattern).strip().lower():
                return True
    return False


def grade_submission(answers: dict[str, list], questions: list[dict], pass_threshold: float) -> GradeResult:
    score = 0.0; max_score = 0.0; per_item = []
    for q in questions:
        w = float(q.get("weight", 1)); max_score += w
        chosen = list(answers.get(q["ext_id"], []))
        raw_correct = q.get("correct", [])
        qtype = q.get("type", "single")
        opts = q.get("options", [])

        if qtype == "numeric":
            ok, expected = _grade_numeric(chosen, raw_correct, opts)
        elif qtype == "short_text":
            accepted: list = raw_correct if isinstance(raw_correct, list) else [raw_correct]
            ok = _grade_short_text(chosen, accepted, opts)
            expected = accepted
        else:
            expected = list(raw_correct)
            ok = set(chosen) == set(expected)

        if ok:
            score += w
        per_item.append({"id": q["ext_id"], "correct": ok, "chosen": chosen,
                         "expected": expected, "weight": q.get("weight", 1)})
    fraction = (score / max_score) if max_score else 0.0
    return GradeResult(score=score, max_score=max_score, fraction=fraction,
                       passed=(max_score > 0 and fraction >= pass_threshold), per_item=per_item)
