from app.services.grading import grade_submission

QS = [
    {"ext_id": "q1", "type": "single", "correct": ["A"], "weight": 1},
    {"ext_id": "q2", "type": "multi", "correct": ["A", "C"], "weight": 2},
    {"ext_id": "q3", "type": "truefalse", "correct": ["true"], "weight": 1},
]

def test_all_correct_passes():
    r = grade_submission({"q1": ["A"], "q2": ["C", "A"], "q3": ["true"]}, QS, 0.6)
    assert r.score == 4 and r.max_score == 4 and r.fraction == 1.0 and r.passed is True

def test_partial_below_threshold_fails():
    r = grade_submission({"q1": ["A"], "q2": ["A"], "q3": ["false"]}, QS, 0.6)
    assert r.score == 1 and r.max_score == 4 and r.passed is False
    item = next(i for i in r.per_item if i["id"] == "q2")
    assert item["correct"] is False and item["expected"] == ["A", "C"]

def test_empty_bank_is_zero_not_crash():
    r = grade_submission({}, [], 0.6)
    assert r.max_score == 0 and r.fraction == 0.0 and r.passed is False
