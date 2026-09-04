"""Tests — subdomain enumeration and takeover detection."""

from __future__ import annotations

import socket
from unittest import mock

from dribik.models import ScanResult, Scope, ScopeRule
from dribik.subdomains import (
    _load_wordlist,
    _resolve,
    check_subdomain_takeover,
    enumerate_subdomains,
)


def test_resolve_success() -> None:
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    with mock.patch("socket.getaddrinfo", return_value=fake_addrinfo):
        fqdn, ips = _resolve("example.com")
        assert fqdn == "example.com"
        assert ips == ["93.184.216.34"]


def test_resolve_gaierror() -> None:
    with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        fqdn, ips = _resolve("nonexistent.example.test")
        assert fqdn == "nonexistent.example.test"
        assert ips == []


def test_load_wordlist_builtin() -> None:
    words = _load_wordlist("subdomains.txt")
    assert isinstance(words, list)
    assert len(words) > 0
    assert any("www" == w.lower() for w in words)


def test_load_wordlist_nonexistent() -> None:
    words = _load_wordlist("does_not_exist_12345.txt")
    assert words == []


def test_enumerate_subdomains_out_of_scope() -> None:
    scope = Scope(
        allow=[ScopeRule(kind="domain_suffix", value="target.test")],
        deny=[ScopeRule(kind="domain_suffix", value="out.target.test")],
    )
    results = enumerate_subdomains("out.target.test", scope=scope)
    assert results == []


def test_enumerate_subdomains_success() -> None:
    def fake_resolve(fqdn: str) -> tuple[str, list[str]]:
        if fqdn == "api.target.test":
            return fqdn, ["192.0.2.1"]
        return fqdn, []

    scope = Scope(allow=[ScopeRule(kind="domain_suffix", value="target.test")])
    with mock.patch("dribik.subdomains._resolve", side_effect=fake_resolve):
        results = enumerate_subdomains(
            "target.test",
            wordlist=["api", "dev", "staging"],
            max_workers=2,
            scope=scope,
        )

    assert len(results) == 1
    assert results[0]["fqdn"] == "api.target.test"
    assert results[0]["ips"] == ["192.0.2.1"]
    assert results[0]["alive"] is True


def test_enumerate_subdomains_default_wordlist() -> None:
    with mock.patch("dribik.subdomains._resolve", return_value=("mock.test", [])):
        results = enumerate_subdomains("target.test", wordlist=None, max_workers=2)
        assert results == []


def test_check_subdomain_takeover_out_of_scope() -> None:
    scope = Scope(allow=[ScopeRule(kind="domain_suffix", value="target.test")])
    res = check_subdomain_takeover("evil.com", scope=scope)
    assert res["vulnerable"] is False
    assert res["note"] == "Out of scope"


def test_check_subdomain_takeover_unresolved() -> None:
    with mock.patch("dribik.subdomains._resolve", return_value=("dangling.target.test", [])):
        res = check_subdomain_takeover("dangling.target.test")
        assert res["vulnerable"] is True
        assert "Does not resolve" in res["note"]


def test_check_subdomain_takeover_fingerprint_match() -> None:
    resolved = ("blog.target.test", ["192.0.2.10"])
    fake_body = "<html><body>There isn't a GitHub Pages site here.</body></html>"
    scan_resp = ScanResult(url="https://blog.target.test/", status=404, body=fake_body)

    with mock.patch("dribik.subdomains._resolve", return_value=resolved), \
         mock.patch("dribik.subdomains.http_get", return_value=scan_resp):
        res = check_subdomain_takeover("blog.target.test")

    assert res["vulnerable"] is True
    assert res["service"] == "GitHub Pages"
    assert "Matched takeover fingerprint" in res["note"]


def test_check_subdomain_takeover_safe() -> None:
    resolved = ("app.target.test", ["192.0.2.20"])
    scan_resp = ScanResult(url="https://app.target.test/", status=200, body="<html><body>Welcome to App</body></html>")

    with mock.patch("dribik.subdomains._resolve", return_value=resolved), \
         mock.patch("dribik.subdomains.http_get", return_value=scan_resp):
        res = check_subdomain_takeover("app.target.test")

    assert res["vulnerable"] is False
    assert res["service"] == ""


def test_check_subdomain_takeover_fallback_to_http() -> None:
    resolved = ("bucket.target.test", ["192.0.2.30"])
    https_err = ScanResult(url="https://bucket.target.test/", error="Connection refused")
    http_resp = ScanResult(
        url="http://bucket.target.test/",
        status=404,
        body="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
    )

    def fake_http_get(url: str, timeout: int = 8) -> ScanResult:
        if url.startswith("https://"):
            return https_err
        return http_resp

    with mock.patch("dribik.subdomains._resolve", return_value=resolved), \
         mock.patch("dribik.subdomains.http_get", side_effect=fake_http_get):
        res = check_subdomain_takeover("bucket.target.test")

    assert res["vulnerable"] is True
    assert res["service"] == "AWS S3"
