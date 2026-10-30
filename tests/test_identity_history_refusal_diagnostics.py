"""Pure early-refusal diagnostics; no database qualification or connection."""

import re
import traceback

import pytest
from sqlalchemy.engine import Engine

from app.maintenance import identity_history as identity
from app.maintenance import product_adoption as product


class _PreflightFailure:
    def __init__(self, error):
        self.error = error

    def get_transaction(self):
        raise self.error


@pytest.mark.parametrize("interrupt", [False, True])
def test_early_import_refusal_poisoning_and_private_diagnostic(monkeypatch, capsys, interrupt):
    marker = "PRIVATE_IDENTITY_DIAGNOSTIC_SENTINEL"
    error = KeyboardInterrupt(marker) if interrupt else RuntimeError(marker)
    connection = _PreflightFailure(error)
    events = []
    real_poison = product._poison
    real_locations = product._maintenance_refusal_locations

    def poison(actual, handle):
        assert actual is connection and handle is None
        real_poison(actual, handle)
        events.append("poison")

    def locations(actual):
        assert actual is error and events == ["poison"]
        events.append("diagnostic")
        return real_locations(actual)

    monkeypatch.setattr(product, "_poison", poison)
    monkeypatch.setattr(product, "_maintenance_refusal_locations", locations)
    monkeypatch.setattr(Engine, "connect", lambda *a, **k: pytest.fail("no database connection permitted"))
    expected = KeyboardInterrupt if interrupt else identity.IdentityHistoryImportRefused
    with pytest.raises(expected) as refused:
        identity.import_academy_identity_history(connection, None, None)
    if interrupt:
        assert refused.value is error
        assert events == ["poison"]
    else:
        assert events == ["poison", "diagnostic"]
        assert refused.value.__suppress_context__ is True
        message = str(refused.value)
        assert re.fullmatch(
            r"Academy identity history import refused; caller rollback required "
            r"\[maintenance identity_history\.py:\d+(?: > identity_history\.py:\d+)*\]",
            message,
        )
        assert marker not in "".join(traceback.format_exception(refused.value))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
