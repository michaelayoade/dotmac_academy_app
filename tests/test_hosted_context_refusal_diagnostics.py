"""Pure context-boundary diagnostics; never create a resource or connection."""

import re
import traceback
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import product_adoption as product
from app.maintenance import retained_hosted_genesis as hosted


@pytest.mark.parametrize("kind", ["ordinary", "keyboard", "exit"])
def test_context_refusal_poisoning_precedes_safe_diagnostic(monkeypatch, capsys, kind):
    marker = "PRIVATE_HOSTED_CONTEXT_SENTINEL"
    interrupt = {"keyboard": KeyboardInterrupt, "exit": SystemExit}.get(kind)
    failure = interrupt(marker) if interrupt else RuntimeError(marker)
    handle = object.__new__(hosted._Handle)
    connection = object()
    values = {field: object() for field in hosted._FIELDS}
    bindings = SimpleNamespace(**values)
    events = []

    def verify(actual, pairs):
        assert actual is connection and dict(pairs) == values
        events.append("verify")
        if interrupt:
            raise failure
        try:
            hosted._need(False)
        except hosted.HostedGenesisRefused:
            # The existing helper must follow this suppressed owned context
            # without rendering the private outer exception message.
            raise failure from None

    owner = SimpleNamespace(poisoned=False, verify=verify)
    real_locations = product._maintenance_refusal_locations

    def locations(error):
        assert error is failure and owner.poisoned and events == ["verify"]
        events.append("diagnostic")
        return real_locations(error)

    monkeypatch.setitem(hosted._ISSUED, handle, owner)
    monkeypatch.setattr(product, "_maintenance_refusal_locations", locations)
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    expected = interrupt or hosted.HostedGenesisRefused
    with pytest.raises(expected) as refused:
        hosted._verify_context(handle, connection, bindings)
    assert owner.poisoned
    if interrupt:
        assert refused.value is failure and events == ["verify"]
    else:
        assert type(refused.value) is hosted.HostedGenesisRefused
        assert events == ["verify", "diagnostic"]
        assert refused.value.__suppress_context__ is True and refused.value.__cause__ is None
        assert re.fullmatch(
            r"Hosted resource context refused \[maintenance "
            r"retained_hosted_genesis\.py:\d+(?: > retained_hosted_genesis\.py:\d+){0,3}\]",
            str(refused.value),
        )
        assert marker not in "".join(traceback.format_exception(refused.value))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_unissued_context_refuses_without_diagnostic_or_resource(monkeypatch):
    monkeypatch.setattr(
        product, "_maintenance_refusal_locations", lambda *a: pytest.fail("no issued context diagnostic")
    )
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    with pytest.raises(hosted.HostedGenesisRefused, match="^Unissued hosted resource context refused$"):
        hosted._verify_context(object(), object(), object())


def test_diagnostic_failure_preserves_hosted_refusal_and_redaction(monkeypatch):
    handle = object.__new__(hosted._Handle)

    def fail(*args):
        raise RuntimeError("PRIVATE_DIAGNOSTIC_FAILURE_SENTINEL")

    owner = SimpleNamespace(poisoned=False, verify=fail)
    monkeypatch.setitem(hosted._ISSUED, handle, owner)
    monkeypatch.setattr(product, "_maintenance_refusal_locations", fail)
    bindings = SimpleNamespace(**{field: object() for field in hosted._FIELDS})
    with pytest.raises(hosted.HostedGenesisRefused) as refused:
        hosted._verify_context(handle, object(), bindings)
    assert owner.poisoned and refused.value.__suppress_context__ is True
    assert str(refused.value) == "Hosted resource context refused [maintenance unavailable]"
    assert "SENTINEL" not in "".join(traceback.format_exception(refused.value))
