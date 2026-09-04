"""Scope classification — allow / deny / unknown."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from dribik.models import Scope, ScopeRule


def _host_of(asset: str) -> str:
    raw = asset.strip()
    if "://" in raw:
        host = urlsplit(raw).hostname or ""
        return host.lower().rstrip(".")
    return raw.lower().split("/")[0].rstrip(".")


def _rule_matches(rule: ScopeRule, asset: str) -> bool:
    host = _host_of(asset)
    value = rule.value.strip().lower().rstrip(".")
    if rule.kind == "host_exact":
        return host == value
    if rule.kind == "domain_suffix":
        return host == value or host.endswith("." + value)
    if rule.kind == "url_prefix":
        return asset.lower().startswith(rule.value.strip().lower())
    return False


def classify(scope: Scope, asset: str) -> str:
    """Return allow | deny | unknown."""
    if any(_rule_matches(rule, asset) for rule in scope.deny):
        return "deny"
    if any(_rule_matches(rule, asset) for rule in scope.allow):
        return "allow"
    return "unknown"


def in_scope(scope: Scope, asset: str) -> bool:
    return classify(scope, asset) == "allow"


def asset_ref(node_data_type: str, data: dict[str, Any]) -> str:
    if node_data_type == "host":
        return str(data.get("fqdn") or "")
    if node_data_type == "endpoint":
        return str(data.get("url") or "")
    if node_data_type == "domain":
        return str(data.get("name") or "")
    if node_data_type == "js_route":
        return str(data.get("source_url") or data.get("path") or "")
    return str(data.get("name") or "")
