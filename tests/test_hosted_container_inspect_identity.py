"""Pure Docker inspect projection checks; no resource or admission authority."""

from copy import deepcopy
from itertools import permutations

import pytest

from app.maintenance.retained_hosted_genesis import (
    _INSPECT_FIELDS,
    HostedGenesisRefused,
    _canonical_mounts,
    _require_container_identity,
)

MOUNTS = [
    {"Type": "bind", "Source": "/private/socket", "Destination": "/var/run/postgresql", "RW": True},
    {"Type": "bind", "Source": "/private/data", "Destination": "/var/lib/postgresql/data", "RW": True},
    {"Type": "bind", "Source": "/private/control", "Destination": "/academy-control", "RW": False},
]


def _identity(mounts):
    fields = list(range(len(_INSPECT_FIELDS)))
    fields[9] = _canonical_mounts(mounts)
    return tuple(fields)


def test_mount_enumeration_order_does_not_change_binding_identity():
    expected = _identity(MOUNTS)
    for order in permutations(MOUNTS):
        _require_container_identity(_identity(list(order)), expected)


@pytest.mark.parametrize("key", ["Type", "Source", "Destination", "RW", "Propagation", "unexpected"])
def test_every_changed_or_additional_mount_attribute_still_refuses(key):
    changed = deepcopy(MOUNTS)
    changed[0][key] = "opaque-value-must-not-leak"
    with pytest.raises(HostedGenesisRefused, match="^Academy hosted container continuity changed: mounts$"):
        _require_container_identity(_identity(changed), _identity(MOUNTS))


def test_missing_or_duplicate_mount_is_not_normalized_away():
    for changed in (MOUNTS[:-1], [*MOUNTS, MOUNTS[0]]):
        with pytest.raises(HostedGenesisRefused):
            _require_container_identity(_identity(changed), _identity(MOUNTS))


def test_non_mount_identity_changes_still_refuse():
    expected = _identity(MOUNTS)
    changed = list(expected)
    changed[1] = "unreviewed-image"
    with pytest.raises(HostedGenesisRefused, match="continuity changed: image_id$"):
        _require_container_identity(tuple(changed), expected)
