"""Assessment-mode reveal policy (practice / graded / exam)."""

from __future__ import annotations

from types import SimpleNamespace

from app.services.assessment import reveal_feedback


def _act(mode, max_attempts=None):
    return SimpleNamespace(assessment_mode=mode, max_attempts=max_attempts)


def test_practice_always_reveals():
    assert reveal_feedback(_act("practice"), passed=False, attempts_used=0) is True


def test_exam_never_reveals_even_when_passed():
    assert reveal_feedback(_act("exam", max_attempts=1), passed=True, attempts_used=1) is False


def test_graded_reveals_on_pass():
    assert reveal_feedback(_act("graded", max_attempts=3), passed=True, attempts_used=1) is True


def test_graded_withholds_until_resolved():
    assert reveal_feedback(_act("graded", max_attempts=3), passed=False, attempts_used=1) is False


def test_graded_reveals_when_attempts_exhausted():
    assert reveal_feedback(_act("graded", max_attempts=3), passed=False, attempts_used=3) is True


def test_graded_unlimited_withholds_until_pass():
    # No cap → "exhausted" never happens, so answers stay hidden until a pass.
    assert reveal_feedback(_act("graded", max_attempts=None), passed=False, attempts_used=99) is False
