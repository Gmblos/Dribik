"""Tests — consent logic (migrated to dribik)."""
import pytest

from dribik.consent import grant, has_consent, require
from dribik.models import ConsentLog


def test_consent_required_for_active_capability():
    log = ConsentLog()
    assert not has_consent(log, "api.example-program.test", "active_exploitation")
    grant(
        log,
        target="api.example-program.test",
        capability="active_exploitation",
        operator="alice",
        note="SOW-1",
    )
    assert has_consent(log, "api.example-program.test", "active_exploitation")
    require(log, "api.example-program.test", "active_exploitation")
    with pytest.raises(PermissionError):
        require(log, "other.test", "active_exploitation")


def test_consent_case_insensitive():
    log = ConsentLog()
    grant(log, target="API.example.test", capability="passive_import", operator="bob")
    assert has_consent(log, "api.example.test", "passive_import")


def test_consent_wrong_capability_not_granted():
    log = ConsentLog()
    grant(log, target="api.example.test", capability="passive_import", operator="bob")
    assert not has_consent(log, "api.example.test", "active_exploitation")
