"""Security header checker — HSTS, CSP, CORS, X-Frame-Options, and more."""

from __future__ import annotations

import uuid

from dribik.models import CVSSVector, Finding, HeaderCheckResult, ScanResult, Scope, Severity
from dribik.scanner import http_get
from dribik.scope import classify

# Header policy definitions: (header_name, severity_if_missing, note)
_REQUIRED_HEADERS: list[tuple[str, Severity, str]] = [
    (
        "strict-transport-security",
        "medium",
        "Missing HSTS header. Browsers may connect over plain HTTP, enabling MitM attacks.",
    ),
    (
        "content-security-policy",
        "medium",
        "Missing Content-Security-Policy. Increases XSS attack surface.",
    ),
    (
        "x-frame-options",
        "medium",
        "Missing X-Frame-Options. Page may be embeddable in iframes (clickjacking risk).",
    ),
    (
        "x-content-type-options",
        "low",
        "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses.",
    ),
    (
        "referrer-policy",
        "info",
        "Missing Referrer-Policy. Referrer header may leak sensitive URL data.",
    ),
    (
        "permissions-policy",
        "info",
        "Missing Permissions-Policy (formerly Feature-Policy).",
    ),
]

_CORS_HEADER = "access-control-allow-origin"
_CORS_CREDS  = "access-control-allow-credentials"


def check_security_headers(
    url: str,
    *,
    timeout: int = 10,
    asset_id: str = "",
    scope: Scope | None = None,
) -> tuple[list[HeaderCheckResult], list[Finding]]:
    """
    Fetch *url* and evaluate its HTTP security headers.

    Returns:
        (header_results, findings)
        - header_results: raw check-by-check results
        - findings: Finding objects for exploitable issues
    """
    if scope and classify(scope, url) != "allow":
        return [], []
    result = http_get(url, timeout=timeout)
    if result.error:
        return [], []
    return _evaluate(result, asset_id or url)


def evaluate_from_result(result: ScanResult, asset_id: str = "") -> tuple[list[HeaderCheckResult], list[Finding]]:
    """Evaluate headers from an already-fetched ScanResult (avoids double request)."""
    return _evaluate(result, asset_id or result.url)


def _evaluate(result: ScanResult, asset_id: str) -> tuple[list[HeaderCheckResult], list[Finding]]:
    headers = {k.lower(): v for k, v in result.headers.items()}
    checks: list[HeaderCheckResult] = []
    findings: list[Finding] = []

    # ---- Required headers ----
    for header, severity, note in _REQUIRED_HEADERS:
        present = header in headers
        checks.append(
            HeaderCheckResult(
                header=header,
                present=present,
                value=headers.get(header, ""),
                severity=severity if not present else "info",
                note="" if present else note,
            )
        )
        if not present:
            fid = f"HDR-{uuid.uuid4().hex[:8].upper()}"
            findings.append(
                Finding(
                    id=fid,
                    title=f"Missing security header: {header}",
                    severity=severity,
                    vuln_type="MissingSecurityHeader",
                    asset_id=asset_id,
                    summary=note,
                    remediation=f"Add the '{header}' response header with an appropriate value.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                    cwe_id="CWE-693",
                    cvss=CVSSVector(vector_string="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
                    response_diff_agreement=1.0,
                )
            )

    # ---- CORS misconfiguration ----
    acao = headers.get(_CORS_HEADER, "")
    acac = headers.get(_CORS_CREDS, "").lower()
    if acao == "*" and acac == "true":
        # This combination is normally rejected by browsers but still worth flagging
        checks.append(
            HeaderCheckResult(
                header=_CORS_HEADER,
                present=True,
                value=acao,
                severity="high",
                note="CORS wildcard with credentials — browsers block but indicates misconfiguration.",
            )
        )
        findings.append(
            Finding(
                id=f"CORS-{uuid.uuid4().hex[:8].upper()}",
                title="CORS Misconfiguration: Wildcard origin with credentials",
                severity="high",
                vuln_type="CORSMisconfiguration",
                asset_id=asset_id,
                summary=(
                    "The server returns Access-Control-Allow-Origin: * alongside "
                    "Access-Control-Allow-Credentials: true, which indicates a CORS misconfiguration."
                ),
                remediation=(
                    "Specify an explicit origin allowlist instead of wildcard. "
                    "Never combine wildcard ACAO with Allow-Credentials: true."
                ),
                references=[
                    "https://portswigger.net/web-security/cors",
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                ],
                cwe_id="CWE-942",
                cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"),
                response_diff_agreement=1.0,
            )
        )
    elif acao and acao not in ("*",):
        # Non-wildcard — check for null or reflected-origin patterns
        if acao.lower() in ("null", "file://"):
            findings.append(
                Finding(
                    id=f"CORS-{uuid.uuid4().hex[:8].upper()}",
                    title="CORS Misconfiguration: Null origin allowed",
                    severity="medium",
                    vuln_type="CORSMisconfiguration",
                    asset_id=asset_id,
                    summary="Server allows CORS requests from the 'null' origin, exploitable via sandboxed iframes.",
                    remediation="Remove 'null' from the CORS origin allowlist.",
                    references=["https://portswigger.net/web-security/cors"],
                    cwe_id="CWE-942",
                    cvss=CVSSVector(vector_string="AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N"),
                    response_diff_agreement=1.0,
                )
            )

    return checks, findings
