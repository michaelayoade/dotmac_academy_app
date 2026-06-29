from __future__ import annotations
from dataclasses import dataclass


_CHOICE_TYPES = {"single", "multi", "truefalse"}
_TEXT_EXACT_TYPES = {"fill_blank", "short_text"}
_TEXT_CONTAINS_TYPES = {"long_text"}

@dataclass
class GradeResult:
    score: float; max_score: float; fraction: float; passed: bool; per_item: list[dict]

def _norm(value: object) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _first_answer(chosen: list) -> str:
    return str(chosen[0]) if chosen else ""


def _is_correct(q: dict, chosen: list) -> bool:
    expected = list(q.get("correct", []))
    qtype = q.get("type")
    if qtype in _CHOICE_TYPES:
        return set(chosen) == set(expected)
    if qtype in _TEXT_EXACT_TYPES:
        answer = _norm(_first_answer(chosen))
        return bool(answer) and answer in {_norm(item) for item in expected}
    if qtype in _TEXT_CONTAINS_TYPES:
        answer = _norm(_first_answer(chosen))
        required = [_norm(item) for item in expected]
        return bool(answer) and bool(required) and all(item in answer for item in required)
    return set(chosen) == set(expected)


def grade_submission(answers: dict[str, list], questions: list[dict], pass_threshold: float) -> GradeResult:
    score = 0.0; max_score = 0.0; per_item = []
    for q in questions:
        w = float(q.get("weight", 1)); max_score += w
        chosen = list(answers.get(q["ext_id"], []))
        expected = list(q.get("correct", []))
        ok = _is_correct(q, chosen)
        if ok:
            score += w
        per_item.append({"id": q["ext_id"], "correct": ok, "chosen": chosen,
                         "expected": expected, "weight": q.get("weight", 1)})
    fraction = (score / max_score) if max_score else 0.0
    return GradeResult(score=score, max_score=max_score, fraction=fraction,
                       passed=(max_score > 0 and fraction >= pass_threshold), per_item=per_item)
