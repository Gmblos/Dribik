"""Open Redirect — GET + POST; scope-aware; full body + Location header check."""

from __future__ import annotations

import urllib.parse
import uuid
from pathlib import Path

from dribik.models import CVSSVector, Finding, ScanResult, Scope
from dribik.scanner import http_get, http_post
from dribik.scope import classify


def _load_payloads() -> list[str]:
    p = Path(__file__).parent.parent / "payloads" / "open_redirect.txt"
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return _BUILTIN


_BUILTIN = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "%2F%2Fevil.com",
    "https://evil.com%2F@target.com",
    "https://target.com@evil.com",
]

_EVIL_DOMAIN = "evil.com"

_REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "next", "target",
    "dest", "destination", "redir", "return", "return_url", "returnTo",
    "go", "url", "link", "continue", "forward", "location", "out",
    "checkout_url", "image_url", "success_url", "cancel_url",
]


def _inject_get(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    qp = dict(urllib.parse.parse_qsl(parsed.query))
    qp[param] = payload
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(qp)))


def _is_redirected(result: ScanResult) -> bool:
    location = result.headers.get("location", "")
    if _EVIL_DOMAIN in location.lower():
        return True
    return any(_EVIL_DOMAIN in u.lower() for u in result.redirect_chain)


def _make_finding(
    param: str, url: str, payload: str, result: ScanResult, asset_id: str, injection_type: str
) -> Finding:
    fid = f"REDIR-{uuid.uuid4().hex[:8].upper()}"
    return Finding(
        id=fid,
        title=f"Open Redirect via {injection_type} parameter '{param}'",
        severity="medium",
        vuln_type="OpenRedirect",
        asset_id=asset_id or url,
        summary=(
            f"The {injection_type} parameter '{param}' redirects users to arbitrary URLs. "
            f"Payload '{payload}' triggered a redirect to an external domain."
        ),
        proof_of_concept=(
            f"Method: {injection_type}\nURL: {url}\n"
            f"Payload: {payload}\nStatus: {result.status}\n"
            f"Location: {result.headers.get('location', '')}"
        ),
        remediation=(
            "Validate redirect targets against an allowlist of permitted domains. "
            "If cross-domain redirects are not needed, reject any redirect parameter "
            "containing an absolute URL."
        ),
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/04-Testing_for_Client_Side_URL_Redirect",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
        cwe_id="CWE-601",
        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        response_diff_agreement=1.0,
    )


def scan_open_redirect(
    url: str,
    *,
    params: list[str] | None = None,
    payloads: list[str] | None = None,
    timeout: int = 10,
    asset_id: str = "",
    scope: Scope | None = None,
    test_post: bool = True,
) -> list[Finding]:
    """Probe GET params and POST body for open redirect vulnerabilities."""
    if scope and classify(scope, url) != "allow":
        return []

    if payloads is None:
        payloads = _load_payloads()

    parsed = urllib.parse.urlsplit(url)
    existing = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    probe_params = params or list(dict.fromkeys(existing + _REDIRECT_PARAMS))

    findings: list[Finding] = []
    seen: set[str] = set()

    for param in probe_params:
        for payload in payloads:
            # GET
            dedup_get = f"redirect:get:{param}"
            if dedup_get not in seen:
                injected = _inject_get(url, param, payload)
                # Keep the 3xx response so Location can be evaluated directly.
                result = http_get(injected, timeout=timeout, follow_redirects=False)
                if not result.error and (result.status in (301, 302, 303, 307, 308) and _is_redirected(result)):
                    seen.add(dedup_get)
                    findings.append(_make_finding(param, injected, payload, result, asset_id, "GET query"))
                    continue

            # POST
            if test_post:
                dedup_post = f"redirect:post:{param}"
                if dedup_post not in seen:
                    result = http_post(url, data={param: payload}, timeout=timeout)
                    if not result.error and (result.status in (301, 302, 303, 307, 308) and _is_redirected(result)):
                        seen.add(dedup_post)
                        findings.append(_make_finding(param, url, payload, result, asset_id, "POST body"))

    return findings
