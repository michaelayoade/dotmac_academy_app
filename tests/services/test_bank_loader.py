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
