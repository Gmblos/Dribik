"""XSS detection — reflected XSS across GET params and POST body, scope-aware."""

from __future__ import annotations

import urllib.parse
import uuid
from pathlib import Path

from dribik.models import CVSSVector, Finding, Scope
from dribik.scanner import http_get, http_post
from dribik.scope import classify


def _load_payloads() -> list[str]:
    p = Path(__file__).parent.parent / "payloads" / "xss.txt"
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return _BUILTIN_PAYLOADS


_BUILTIN_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
]


def _inject_get(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    qp = dict(urllib.parse.parse_qsl(parsed.query))
    qp[param] = payload
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(qp)))


def _make_finding(param: str, url: str, payload: str, result, asset_id: str, injection_type: str) -> Finding:
    fid = f"XSS-{uuid.uuid4().hex[:8].upper()}"
    return Finding(
        id=fid,
        title=f"Reflected XSS in {injection_type} parameter '{param}'",
        severity="high",
        vuln_type="XSS",
        asset_id=asset_id or url,
        summary=(
            f"The {injection_type} parameter '{param}' reflects user input without encoding. "
            f"Payload `{payload[:80]}` was echoed back in the response."
        ),
        proof_of_concept=(
            f"Method: {result.method}\nURL: {url}\n"
            f"Parameter: {param} ({injection_type})\nPayload: {payload}\n"
            f"Response status: {result.status}"
        ),
        remediation=(
            "Encode all user-supplied output with context-appropriate escaping "
            "(HTML entity encoding for HTML context). "
            "Apply a strict Content-Security-Policy header."
        ),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-79",
        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        response_diff_agreement=1.0,
    )


def scan_xss(
    url: str,
    *,
    params: list[str] | None = None,
    payloads: list[str] | None = None,
    timeout: int = 10,
    asset_id: str = "",
    scope: Scope | None = None,
    test_post: bool = True,
) -> list[Finding]:
    """
    Probe URL parameters (GET + POST body) for reflected XSS.
    Scope-aware: skips the URL if it doesn't match the scope.
    Rate limiting is handled by the global scanner rate limiter.
    """
    if scope and classify(scope, url) != "allow":
        return []

    if payloads is None:
        payloads = _load_payloads()

    parsed = urllib.parse.urlsplit(url)
    existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    common_params = ["q", "search", "id", "name", "input", "query", "s", "term", "keyword"]
    probe_params = params or list(dict.fromkeys(existing_params + common_params))

    findings: list[Finding] = []
    seen: set[str] = set()

    for param in probe_params:
        for payload in payloads:
            # --- GET query param ---
            injected_url = _inject_get(url, param, payload)
            result = http_get(injected_url, timeout=timeout)
            if not result.error and payload.lower() in result.body.lower():
                dedup_key = f"xss:get:{param}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(_make_finding(param, injected_url, payload, result, asset_id, "GET query"))
                break

            # --- POST body param ---
            if test_post:
                post_result = http_post(url, data={param: payload}, timeout=timeout)
                if not post_result.error and payload.lower() in post_result.body.lower():
                    dedup_key = f"xss:post:{param}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append(_make_finding(param, url, payload, post_result, asset_id, "POST body"))
                    break

    return findings
