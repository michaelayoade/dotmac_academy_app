"""Pure early runner refusals; no historical transition/DB qualification."""

import re
import traceback

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import product_adoption as product

RUNNERS = (
    (product._run_retained_transition, "retained"),
    (product._run_checkpoint_transition, "checkpoint"),
    (product._run_lab_claim_lease_transition, "lab claim lease"),
)


@pytest.mark.parametrize("runner,label", RUNNERS)
@pytest.mark.parametrize("interrupt", [False, True])
def test_early_runner_failure_poisoning_and_private_diagnostic(monkeypatch, capsys, runner, label, interrupt):
    marker = "PRIVATE_HISTORICAL_RUNNER_SENTINEL"
    error = KeyboardInterrupt(marker) if interrupt else RuntimeError(marker)
    connection, handle = object(), object()
    events = []
    real_poison = product._poison
    real_locations = product._maintenance_refusal_locations

    def fail_state(actual):
        assert actual is handle
        raise error

    def poison(actual, supplied):
        assert actual is connection and supplied is handle
        real_poison(actual, supplied)
        events.append("poison")

    def locations(actual):
        assert actual is error and events == ["poison"]
        events.append("diagnostic")
        return real_locations(actual)

    monkeypatch.setattr(product, "_state_for", fail_state)
    monkeypatch.setattr(product, "_poison", poison)
    monkeypatch.setattr(product, "_maintenance_refusal_locations", locations)
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    monkeypatch.setattr(product, "ordinary_migration_config", lambda **k: pytest.fail("must refuse before graph setup"))
    expected = KeyboardInterrupt if interrupt else product.ProductAdoptionRefused
    with pytest.raises(expected) as refused:
        # Real runner -> real _check; injected state lookup failure occurs
        # before a resource, graph, transition state or SQL can be acquired.
        runner(connection, handle)
    if interrupt:
        assert refused.value is error
        assert events == ["poison"]
    else:
        assert events == ["poison", "diagnostic"]
        assert refused.value.__suppress_context__ is True
        assert re.fullmatch(
            rf"Academy {label} runner refused; root rollback required "
            r"\[maintenance product_adoption\.py:\d+(?: > product_adoption\.py:\d+)*\]",
            str(refused.value),
        )
        assert marker not in "".join(traceback.format_exception(refused.value))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("runner,label", RUNNERS)
def test_actual_unissued_handle_refusal_still_precedes_runner_setup(monkeypatch, runner, label):
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    monkeypatch.setattr(product, "ordinary_migration_config", lambda **k: pytest.fail("must refuse before graph setup"))
    with pytest.raises(product.ProductAdoptionRefused) as refused:
        runner(object(), object())
    assert str(refused.value).startswith(f"Academy {label} runner refused; root rollback required [maintenance ")
    assert refused.value.__suppress_context__ is True
