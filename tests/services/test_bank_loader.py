from pathlib import Path

from app.models.assessment import Question
from app.models.course import Course
from app.services.bank_loader import lint_bank, load_bank, parse_bank

FX = Path(__file__).resolve().parent.parent / "fixtures" / "banks" / "foundation-ch3.yaml"

def test_lint_passes_on_balanced_bank():
    assert lint_bank(parse_bank(FX)) == []

def test_lint_flags_bad_correct():
    doc = parse_bank(FX)
    doc.questions[0]["correct"] = ["Z"]  # not an option
    assert any("not in options" in v for v in lint_bank(doc))

def test_lint_flags_answer_that_is_always_the_longest_option():
    """A bank whose answer is spottable by length measures nothing."""
    doc = parse_bank(FX)
    for q in doc.questions:
        correct = q["correct"][0]
        q["options"] = [correct + " because of the full careful reasoning", "No", "Yes", "Maybe"]
        q["correct"] = [correct + " because of the full careful reasoning"]
    violations = lint_bank(doc)
    assert any("correct answer is the longest option" in v for v in violations)
    assert any("the length of their distractors" in v for v in violations)

def test_lint_flags_answer_that_is_always_the_shortest_option():
    """Over-correcting a long-answer bank produces the same tell, inverted."""
    doc = parse_bank(FX)
    for q in doc.questions:
        q["options"] = ["Yes", "No because the reasoning runs on", "Maybe, on the other hand",
                        "It depends on several conditions"]
        q["correct"] = ["Yes"]
    violations = lint_bank(doc)
    assert any("the shortest option" in v for v in violations)
    assert any("consistently shorter" in v for v in violations)

def test_lint_ignores_length_ties():
    """Several options sharing the top length leak no signal, so they don't count."""
    doc = parse_bank(FX)
    for q in doc.questions:
        q["options"] = ["AAAA", "BBBB", "CCCC", "DDDD"]
        q["correct"] = ["AAAA"]
    assert not any("distractor balance" in v for v in lint_bank(doc))

def test_lint_ignores_truefalse_options():
    """"false" is one character longer than "true"; that is not an authoring choice."""
    doc = parse_bank(FX)
    for q in doc.questions:
        q["type"] = "truefalse"
        q["options"] = ["true", "false"]
        q["correct"] = ["false"]
    assert not any("distractor balance" in v for v in lint_bank(doc))

def test_lint_skips_balance_check_on_small_banks():
    """Under five comparable questions, one item swings the share meaninglessly."""
    doc = parse_bank(FX)
    doc.questions = doc.questions[:4]
    for q in doc.questions:
        q["options"] = ["A much longer correct answer here", "No", "Yes", "Maybe"]
        q["correct"] = ["A much longer correct answer here"]
        q["rubric_category"] = "application"
    assert not any("distractor balance" in v for v in lint_bank(doc))

def test_lint_does_not_penalise_multi_for_containing_the_longest_option():
    """A multi question with several answers holds the longest string by construction."""
    doc = parse_bank(FX)
    for q in doc.questions:
        q["type"] = "multi"
        q["options"] = ["Alpha item here", "Beta item here", "Gamma item here", "Delta item"]
        q["correct"] = ["Alpha item here", "Beta item here", "Gamma item here"]
    assert not any("longest option" in v for v in lint_bank(doc))

def test_parse_bank_defaults_to_no_policy():
    """A bank without a policy block leaves the activity's settings alone."""
    assert parse_bank(FX).policy == {}

def test_lint_accepts_a_valid_policy():
    doc = parse_bank(FX)
    doc.policy = {"pool": 5, "max_attempts": 3, "mode": "exam"}
    assert not any("policy" in v for v in lint_bank(doc))

def test_lint_rejects_a_pool_that_holds_nothing_back():
    """A pool at or above the bank size draws everything, which is the old behaviour."""
    doc = parse_bank(FX)
    doc.policy = {"pool": len(doc.questions) + 1}
    assert any("nothing is held back" in v for v in lint_bank(doc))

def test_lint_rejects_unknown_policy_keys_and_bad_values():
    doc = parse_bank(FX)
    doc.policy = {"timed": 600, "mode": "proctored", "max_attempts": 0}
    violations = lint_bank(doc)
    assert any("unknown key(s) timed" in v for v in violations)
    assert any("mode must be one of" in v for v in violations)
    assert any("max_attempts must be a positive integer" in v for v in violations)

def test_load_bank(admin_session, tenant_a):
    c = Course(tenant_id=tenant_a.id, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    admin_session.add(c); admin_session.flush()
    bank = load_bank(admin_session, tenant_id=tenant_a.id, course_id=c.id, doc=parse_bank(FX))
    admin_session.flush()
    n = admin_session.query(Question).filter(Question.bank_id == bank.id).count()
    assert n == 10
    admin_session.rollback()

def test_load_bank_replaces_on_reload(admin_session, tenant_a):
    c = Course(tenant_id=tenant_a.id, slug="foundation", title="F",
               discipline="networking", source_ref="x", version=1)
    admin_session.add(c); admin_session.flush()
    bank1 = load_bank(admin_session, tenant_id=tenant_a.id, course_id=c.id, doc=parse_bank(FX))
    admin_session.flush()
    bank2 = load_bank(admin_session, tenant_id=tenant_a.id, course_id=c.id, doc=parse_bank(FX))
    admin_session.flush()
    assert bank1.id == bank2.id
    assert admin_session.query(Question).filter(Question.bank_id == bank2.id).count() == 10
    admin_session.rollback()

def test_lint_checks_balance_within_each_competency_category():
    """A bank can look balanced overall while one competency is fully guessable."""
    doc = parse_bank(FX)
    doc.questions = []
    for i in range(6):  # safety: answer always the longest
        doc.questions.append({
            "id": f"safe-{i}", "type": "single", "category": "safety",
            "options": [f"The full careful safety answer number {i}", "No", "Yes", "Maybe"],
            "correct": [f"The full careful safety answer number {i}"],
            "rubric_category": "application", "weight": 1,
        })
    for i in range(14):  # numeracy: balanced, and enough to mask it in the total
        doc.questions.append({
            "id": f"num-{i}", "type": "single", "category": "numeracy",
            "options": ["AAAA", "BBBB", "CCCC", "DDDD"], "correct": ["AAAA"],
            "rubric_category": "application" if i > 3 else "recall", "weight": 1,
        })
    violations = lint_bank(doc)
    assert any(v.startswith("safety: distractor balance") for v in violations)
    assert not any(v.startswith("numeracy: distractor balance") for v in violations)

def test_lint_skips_category_check_when_there_is_only_one():
    """A single-category bank is already covered by the bank-level check."""
    doc = parse_bank(FX)
    for q in doc.questions:
        q["category"] = "general"
    assert not any(v.startswith("general:") for v in lint_bank(doc))
