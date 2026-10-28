"""The attempt entitlement, and the grant that changes it.

The arithmetic is tested without a database wherever it can be, because the
whole point of the module is that five callers share one expression — a pure
function they can all reach is what makes that true.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.services import attempt_policy


class _Activity:
    """Only what the entitlement reads."""

    def __init__(self, max_attempts):
        self.max_attempts = max_attempts


def test_uncapped_activity_is_never_exhausted():
    ent = attempt_policy.entitlement(_Activity(None), used=99)
    assert ent.exhausted is False
    # None, not a large number: callers render "unlimited", and a number would
    # invite them to count down from it.
    assert ent.remaining is None


def test_capped_activity_counts_down_and_then_exhausts():
    act = _Activity(3)
    assert attempt_policy.entitlement(act, used=0).remaining == 3
    assert attempt_policy.entitlement(act, used=2).remaining == 1
    assert attempt_policy.entitlement(act, used=2).exhausted is False
    assert attempt_policy.entitlement(act, used=3).exhausted is True


def test_remaining_never_goes_negative():
    """A grant withdrawn by lowering max_attempts must not render as -1 left."""
    assert attempt_policy.entitlement(_Activity(2), used=5).remaining == 0


def test_a_grant_raises_the_limit_for_that_learner_only():
    """The whole reason grants exist: max_attempts alone reopens it for everyone."""
    act = _Activity(2)
    assert attempt_policy.entitlement(act, used=2).exhausted is True
    assert attempt_policy.entitlement(act, used=2, granted=1).exhausted is False
    assert attempt_policy.entitlement(act, used=2, granted=1).remaining == 1


def test_grants_accumulate():
    """Two separate grants of one are three attempts, not two."""
    assert attempt_policy.entitlement(_Activity(1), used=1, granted=2).remaining == 2


def test_a_grant_on_an_uncapped_activity_changes_nothing():
    ent = attempt_policy.entitlement(_Activity(None), used=4, granted=3)
    assert ent.limit is None and ent.exhausted is False


@pytest.mark.parametrize(
    "max_attempts, used, granted, limit, remaining, exhausted",
    [
        (3, 2, 0, 3, 1, False),
        (3, 3, 0, 3, 0, True),
        (2, 2, 1, 3, 1, False),
        (1, 1, 2, 3, 2, False),
        (2, 5, 0, 2, 0, True),
        (None, 99, 3, None, None, False),
    ],
)
def test_entitlement_with_grants_reads_bound_total_once(
    max_attempts, used, granted, limit, remaining, exhausted
):
    class Reader:
        calls = 0

        def total(self):
            self.calls += 1
            return granted

    reader = Reader()
    ent = attempt_policy.entitlement_with_grants(
        _Activity(max_attempts), used=used, reader=reader
    )

    assert ent == attempt_policy.Entitlement(used=used, granted=granted, limit=limit)
    assert ent.remaining == remaining
    assert ent.exhausted is exhausted
    assert reader.calls == 1


def test_entitlement_with_grants_propagates_reader_failure():
    failure = RuntimeError("grant read failed")

    class Reader:
        def total(self):
            raise failure

    with pytest.raises(RuntimeError) as raised:
        attempt_policy.entitlement_with_grants(_Activity(2), used=1, reader=Reader())

    assert raised.value is failure


def test_for_learner_uses_supplied_session_and_exact_grant_scope(monkeypatch):
    db = object()
    tenant_id, person_id, activity_id = uuid4(), uuid4(), uuid4()
    activity = _Activity(2)
    activity.id = activity_id
    calls = []
    narrow_calls = []
    narrow_entry = attempt_policy.entitlement_with_grants

    def granted_for(supplied_db, *, tenant_id, person_id, activity_id):
        calls.append((supplied_db, tenant_id, person_id, activity_id))
        return 3

    def entitlement_with_grants(supplied_activity, *, used, reader):
        narrow_calls.append((supplied_activity, used))
        return narrow_entry(supplied_activity, used=used, reader=reader)

    monkeypatch.setattr(attempt_policy, "granted_for", granted_for)
    monkeypatch.setattr(attempt_policy, "entitlement_with_grants", entitlement_with_grants)

    ent = attempt_policy.for_learner(
        db, tenant_id=tenant_id, person_id=person_id, activity=activity, used=4
    )

    assert len(calls) == 1
    supplied_db, supplied_tenant, supplied_person, supplied_activity = calls[0]
    assert supplied_db is db
    assert supplied_tenant is tenant_id
    assert supplied_person is person_id
    assert supplied_activity is activity_id
    assert narrow_calls == [(activity, 4)]
    assert ent == attempt_policy.Entitlement(used=4, granted=3, limit=5)
    assert ent.remaining == 1
    assert ent.exhausted is False


def test_grant_requires_a_reason():
    """A grant reopens a graded assessment for one person; the next
    administrator to look needs to know whether that was a power cut or a favour."""
    with pytest.raises(ValueError, match="why"):
        attempt_policy.grant_extra_attempt(
            None, tenant_id=None, person_id=None, activity_id=None, reason="   "
        )


def test_grant_must_add_at_least_one_attempt():
    with pytest.raises(ValueError, match="at least one"):
        attempt_policy.grant_extra_attempt(
            None, tenant_id=None, person_id=None, activity_id=None,
            reason="power cut", extra_attempts=0,
        )


def test_reveal_feedback_does_not_leak_the_key_before_a_granted_retake():
    """The failure this prevents.

    On a graded activity the answer key is revealed once attempts are spent.
    Granting a retake after that would hand the learner the answers to the
    attempt they are about to sit — so the reveal has to consult the same
    entitlement the submit path does, grants included.
    """
    from app.services.assessment import reveal_feedback

    act = _Activity(1)
    act.assessment_mode = "graded"

    # Spent, not passed: the key is shown, which is the point of the mode.
    assert reveal_feedback(act, passed=False, attempts_used=1) is True
    # ...but once a retake is granted, it is no longer spent, and the key closes.
    assert reveal_feedback(act, passed=False, attempts_used=1, attempts_granted=1) is False
