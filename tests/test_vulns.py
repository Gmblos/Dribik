"""Tests — vulnerability modules (new for dribik).

All tests are pure-logic / offline. They use unittest.mock to patch
the HTTP layer so no real network calls are made.
"""
from __future__ import annotations

import json
from unittest import mock

from dribik.models import ScanResult
from dribik.scanner import http_get
from dribik.vulns.headers import evaluate_from_result
from dribik.vulns.jwt_audit import _b64url_encode, _decode_jwt, audit_jwt
from dribik.vulns.lfi import scan_lfi
from dribik.vulns.open_redirect import scan_open_redirect
from dribik.vulns.sqli import scan_sqli
from dribik.vulns.xss import scan_xss

# ---------------------------------------------------------------------------
# JWT audit — pure logic, no HTTP
# ---------------------------------------------------------------------------


def _make_jwt(header: dict, payload: dict, secret: str = "", alg: str = "HS256") -> str:
    """Craft a minimal JWT for testing."""
    import hashlib
    import hmac
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none":
        return f"{h}.{p}."
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    s = _b64url_encode(sig)
    return f"{h}.{p}.{s}"


def test_jwt_decode_valid():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1234"}, secret="secret")
    decoded = _decode_jwt(token)
    assert decoded is not None
    header, payload, _ = decoded
    assert header["alg"] == "HS256"
    assert payload["sub"] == "1234"


def test_jwt_decode_invalid():
    assert _decode_jwt("not.a.jwt.at.all") is None
    assert _decode_jwt("") is None


def test_jwt_audit_alg_none_flag():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1"}, secret="secret")
    findings = audit_jwt(token)
    titles = [f.title for f in findings]
    assert any("alg:none" in t for t in titles)


def test_jwt_audit_weak_secret_detected():
    # Craft token signed with the word "secret" (in our built-in wordlist)
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, secret="secret", alg="HS256")
    findings = audit_jwt(token)
    titles = [f.title for f in findings]
    assert any("Weak HMAC secret" in t for t in titles)


def test_jwt_audit_kid_header_flagged():
    token = _make_jwt({"alg": "HS256", "typ": "JWT", "kid": "../../dev/null"}, {"sub": "x"}, secret="s")
    findings = audit_jwt(token)
    titles = [f.title for f in findings]
    assert any("kid" in t.lower() for t in titles)


def test_jwt_audit_all_findings_have_cwe():
    token = _make_jwt({"alg": "HS256", "typ": "JWT", "kid": "1"}, {"sub": "x"}, secret="secret")
    findings = audit_jwt(token)
    for f in findings:
        assert f.cwe_id, f"Finding {f.id} is missing cwe_id"


# ---------------------------------------------------------------------------
# XSS — mock HTTP to return payload reflection
# ---------------------------------------------------------------------------


def _mock_result(body: str, status: int = 200) -> ScanResult:
    return ScanResult(url="http://x.test/?q=PAYLOAD", status=status, body=body)


def test_xss_reflected_detected():
    payload = "<script>alert(1)</script>"
    with mock.patch("dribik.vulns.xss.http_get", return_value=_mock_result(f"hello {payload} world")):
        findings = scan_xss("http://x.test/?q=safe", params=["q"], payloads=[payload])
    assert len(findings) == 1
    assert findings[0].vuln_type == "XSS"
    assert findings[0].severity == "high"
    assert findings[0].cwe_id == "CWE-79"


def test_xss_no_reflection_no_finding():
    with mock.patch("dribik.vulns.xss.http_get", return_value=_mock_result("clean response")):
        findings = scan_xss("http://x.test/", params=["q"], payloads=["<script>alert(1)</script>"])
    assert findings == []


# ---------------------------------------------------------------------------
# SQLi — mock HTTP to return DBMS error
# ---------------------------------------------------------------------------


def test_sqli_error_based_detected():
    error_body = "You have an error in your SQL syntax near 'AND 1=1'"
    with mock.patch("dribik.vulns.sqli.http_get", return_value=_mock_result(error_body)):
        findings = scan_sqli("http://x.test/?id=1", params=["id"], payloads=["'"])
    assert len(findings) == 1
    assert findings[0].vuln_type == "SQLi"
    assert findings[0].severity == "critical"
    assert findings[0].cwe_id == "CWE-89"


def test_sqli_clean_response_no_finding():
    with mock.patch("dribik.vulns.sqli.http_get", return_value=_mock_result("hello world")):
        findings = scan_sqli("http://x.test/?id=1", params=["id"], payloads=["'"])
    assert findings == []


# ---------------------------------------------------------------------------
# LFI — mock HTTP to return /etc/passwd content
# ---------------------------------------------------------------------------


def test_lfi_passwd_detected():
    passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    with mock.patch("dribik.vulns.lfi.http_get", return_value=_mock_result(passwd_body)):
        findings = scan_lfi("http://x.test/?file=index.php", params=["file"], payloads=["../../../../etc/passwd"])
    assert len(findings) == 1
    assert findings[0].vuln_type == "LFI"
    assert findings[0].cwe_id == "CWE-22"


# ---------------------------------------------------------------------------
# Security headers — mock HTTP response headers
# ---------------------------------------------------------------------------


def test_headers_missing_hsts_flagged():
    result = ScanResult(
        url="https://x.test/",
        status=200,
        headers={},  # no security headers at all
    )
    checks, findings = evaluate_from_result(result, asset_id="x.test")
    header_names = [c.header for c in checks]
    assert "strict-transport-security" in header_names
    # HSTS missing → finding generated
    finding_titles = [f.title for f in findings]
    assert any("strict-transport-security" in t.lower() for t in finding_titles)


def test_headers_cors_wildcard_with_creds_flagged():
    result = ScanResult(
        url="https://x.test/",
        status=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    _, findings = evaluate_from_result(result, asset_id="x.test")
    assert any("CORS" in f.title for f in findings)
    cors_finding = next(f for f in findings if "CORS" in f.title)
    assert cors_finding.severity == "high"


def test_headers_all_present_no_critical_findings():
    result = ScanResult(
        url="https://x.test/",
        status=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        },
    )
    checks, findings = evaluate_from_result(result, asset_id="x.test")
    critical_findings = [f for f in findings if f.severity in ("critical", "high")]
    assert critical_findings == []


# ---------------------------------------------------------------------------
# Open redirect — mock HTTP returning a redirect to evil.com
# ---------------------------------------------------------------------------


def test_open_redirect_detected():
    redirect_result = ScanResult(
        url="http://x.test/?next=https://evil.com",
        status=302,
        headers={"location": "https://evil.com"},
    )
    with mock.patch("dribik.vulns.open_redirect.http_get", return_value=redirect_result):
        findings = scan_open_redirect("http://x.test/?next=safe", params=["next"], payloads=["https://evil.com"])
    assert len(findings) == 1
    assert findings[0].vuln_type == "OpenRedirect"
    assert findings[0].cwe_id == "CWE-601"


def test_open_redirect_no_redirect_no_finding():
    ok_result = ScanResult(url="http://x.test/", status=200, headers={})
    with mock.patch("dribik.vulns.open_redirect.http_get", return_value=ok_result):
        findings = scan_open_redirect("http://x.test/", params=["next"], payloads=["https://evil.com"])
    assert findings == []


def test_http_get_preserves_redirect_when_requested(monkeypatch):
    import io
    import urllib.error

    def fake_open(self, req, timeout=10):
        raise urllib.error.HTTPError(
            req.full_url, 302, "Found", {"Location": "https://evil.com"}, io.BytesIO()
        )

    monkeypatch.setattr("urllib.request.OpenerDirector.open", fake_open)
    result = http_get("https://example.test/redirect", follow_redirects=False, max_retries=0)
    assert result.status == 302
    assert result.headers["location"] == "https://evil.com"
