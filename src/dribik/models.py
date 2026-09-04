"""Dribik data models — v0.1.0-beta."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, Field, computed_field

# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------
NodeType = Literal["domain", "host", "endpoint", "param", "js_route"]
ParamLocation = Literal["query", "body", "header", "path"]

# Fine-grained capabilities:
#   active_exploitation         — blanket: covers all sub-types below
#   active_exploitation:crawl   — BFS web crawling
#   active_exploitation:content — common-path content discovery
#   active_exploitation:headers — security header probing
#   active_exploitation:xss     — XSS injection
#   active_exploitation:sqli    — SQL injection (including time-based)
#   active_exploitation:ssrf    — SSRF / metadata endpoint probes
#   active_exploitation:lfi     — path traversal / LFI
#   active_exploitation:redirect — open redirect probing
#   active_exploitation:jwt     — JWT audit
Capability = Literal[
    "workspace",
    "passive_import",
    "active_exploitation",
    "active_exploitation:crawl",
    "active_exploitation:content",
    "active_exploitation:headers",
    "active_exploitation:xss",
    "active_exploitation:sqli",
    "active_exploitation:ssrf",
    "active_exploitation:lfi",
    "active_exploitation:redirect",
    "active_exploitation:jwt",
]

VulnType = Literal[
    "XSS",
    "SQLi",
    "SSRF",
    "IDOR",
    "LFI",
    "RCE",
    "OpenRedirect",
    "CSRF",
    "HeaderInjection",
    "JWT",
    "SubdomainTakeover",
    "XXE",
    "BreakAuthentication",
    "MissingSecurityHeader",
    "CORSMisconfiguration",
    "Other",
]

Severity = Literal["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "https").lower()
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    query_pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(query_pairs)
    return urlunsplit((scheme, netloc, path, query, ""))


def host_id(fqdn: str) -> str:
    return f"host:{fqdn.strip().lower().rstrip('.')}"


def endpoint_id(method: str, url: str) -> str:
    return f"endpoint:{(method or 'GET').upper()}:{normalize_url(url)}"


def param_id(parent: str, location: str, name: str) -> str:
    return f"param:{parent}:{location}:{name.lower()}"


def js_route_id(source_url: str, path: str) -> str:
    return f"js_route:{normalize_url(source_url)}:{path}"


def domain_id(name: str) -> str:
    return f"domain:{name.strip().lower().rstrip('.')}"


# ---------------------------------------------------------------------------
# Graph models
# ---------------------------------------------------------------------------
class Source(BaseModel):
    tool: str
    imported_at: str = Field(default_factory=utc_now)


class Node(BaseModel):
    id: str
    type: NodeType
    sources: list[Source] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    src: str
    dst: str
    kind: str = "child"


class Graph(BaseModel):
    schema_version: int = 1
    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)

    def add_edge(self, src: str, dst: str, kind: str = "child") -> None:
        for edge in self.edges:
            if edge.src == src and edge.dst == dst and edge.kind == kind:
                return
        self.edges.append(Edge(src=src, dst=dst, kind=kind))


# ---------------------------------------------------------------------------
# Scope models
# ---------------------------------------------------------------------------
class ScopeRule(BaseModel):
    kind: Literal["domain_suffix", "url_prefix", "host_exact"]
    value: str


class Scope(BaseModel):
    program: str = ""
    allow: list[ScopeRule] = Field(default_factory=list)
    deny: list[ScopeRule] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Consent models
# ---------------------------------------------------------------------------
class ConsentRecord(BaseModel):
    target: str
    capability: Capability
    operator: str
    granted_at: str = Field(default_factory=utc_now)
    expires_at: str | None = None
    note: str = ""


class ConsentLog(BaseModel):
    records: list[ConsentRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# CVSS v3.1 Base Score
# ---------------------------------------------------------------------------
class CVSSVector(BaseModel):
    """CVSS v3.1 base vector string and computed score."""

    vector_string: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def base_score(self) -> float:
        return _compute_cvss_base(self.vector_string)


def _compute_cvss_base(vector: str) -> float:
    if not vector:
        return 0.0
    metrics: dict[str, str] = {}
    for part in vector.upper().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(metrics.get("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", "L"), 0.77)
    scope_changed = metrics.get("S", "U") == "C"
    pr_map = {"N": 0.85, "L": (0.68 if scope_changed else 0.62), "H": (0.50 if scope_changed else 0.27)}
    pr = pr_map.get(metrics.get("PR", "N"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", "N"), 0.85)
    impact_vals = {"N": 0.00, "L": 0.22, "H": 0.56}
    c = impact_vals.get(metrics.get("C", "N"), 0.0)
    i = impact_vals.get(metrics.get("I", "N"), 0.0)
    a = impact_vals.get(metrics.get("A", "N"), 0.0)
    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if isc_base == 0.0:
        return 0.0
    if not scope_changed:
        isc = 6.42 * isc_base
    else:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    exp = 8.22 * av * ac * pr * ui
    if not scope_changed:
        base = min(isc + exp, 10.0)
    else:
        base = min(1.08 * (isc + exp), 10.0)
    return math.ceil(base * 10) / 10


# ---------------------------------------------------------------------------
# Scan result  (body = full response body up to 64 KB — NOT a snippet)
# ---------------------------------------------------------------------------
class ScanResult(BaseModel):
    url: str
    status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""          # Full response body, up to 64 KB
    body_hash: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    response_time_ms: float = 0.0
    error: str | None = None
    method: str = "GET"
    request_body: str = ""  # What was sent (for audit log)

    @property
    def body_snippet(self) -> str:
        """First 500 chars — for display in PoC / reports."""
        return self.body[:500]


# ---------------------------------------------------------------------------
# Audit log entry — one per HTTP request sent to a target
# ---------------------------------------------------------------------------
class AuditEntry(BaseModel):
    timestamp: str = Field(default_factory=utc_now)
    method: str
    url: str
    request_body: str = ""
    status: int | None = None
    response_time_ms: float = 0.0
    error: str | None = None
    tool: str = ""


# ---------------------------------------------------------------------------
# Tech stack fingerprint
# ---------------------------------------------------------------------------
class TechStack(BaseModel):
    server: str = ""
    framework: str = ""
    language: str = ""
    waf: str = ""
    cms: str = ""
    raw_headers: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Security header policy result
# ---------------------------------------------------------------------------
class HeaderCheckResult(BaseModel):
    header: str
    present: bool
    value: str = ""
    severity: Severity = "info"
    note: str = ""


# ---------------------------------------------------------------------------
# Finding (extended for Dribik)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    id: str
    title: str
    severity: Severity = "info"
    vuln_type: VulnType = "Other"
    asset_id: str
    summary: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe_id: str = ""
    cvss: CVSSVector | None = None
    template_age_days: int = 0
    response_diff_agreement: float = 0.0
    operator_validated: bool = False
    confidence: float | None = None
    out_of_scope: bool = False
    discovered_at: str = Field(default_factory=utc_now)

    @property
    def cvss_score(self) -> float:
        return self.cvss.base_score if self.cvss else 0.0


class FindingsFile(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Workspace meta
# ---------------------------------------------------------------------------
class WorkspaceMeta(BaseModel):
    schema_version: int = 1
    program: str
    created_at: str = Field(default_factory=utc_now)
    dribik_version: str = "0.1.0-beta"
