from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GradeResult:
    score: float; max_score: float; fraction: float; passed: bool; per_item: list[dict]

def grade_submission(answers: dict[str, list], questions: list[dict], pass_threshold: float) -> GradeResult:
    score = 0.0; max_score = 0.0; per_item = []
    for q in questions:
        w = float(q.get("weight", 1)); max_score += w
        chosen = list(answers.get(q["ext_id"], []))
        expected = list(q.get("correct", []))
        ok = set(chosen) == set(expected)
        if ok:
            score += w
        per_item.append({"id": q["ext_id"], "correct": ok, "chosen": chosen,
                         "expected": expected, "weight": q.get("weight", 1)})
    fraction = (score / max_score) if max_score else 0.0
    return GradeResult(score=score, max_score=max_score, fraction=fraction,
                       passed=(max_score > 0 and fraction >= pass_threshold), per_item=per_item)
