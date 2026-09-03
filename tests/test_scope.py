"""Tests — scope classification (migrated to dribik)."""
from dribik.models import Scope, ScopeRule
from dribik.scope import classify


def test_suffix_allow_and_exact_deny():
    scope = Scope(
        program="demo",
        allow=[ScopeRule(kind="domain_suffix", value="example-program.test")],
        deny=[ScopeRule(kind="host_exact", value="payments.example-program.test")],
    )
    assert classify(scope, "www.example-program.test") == "allow"
    assert classify(scope, "https://api.example-program.test/v1") == "allow"
    assert classify(scope, "payments.example-program.test") == "deny"
    assert classify(scope, "other.test") == "unknown"
