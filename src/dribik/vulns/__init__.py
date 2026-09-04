"""Vulnerability modules — XSS, SQLi, SSRF, LFI, Headers, JWT, OpenRedirect."""

from __future__ import annotations

from dribik.vulns.headers import check_security_headers
from dribik.vulns.jwt_audit import audit_jwt
from dribik.vulns.lfi import scan_lfi
from dribik.vulns.open_redirect import scan_open_redirect
from dribik.vulns.sqli import scan_sqli
from dribik.vulns.ssrf import scan_ssrf
from dribik.vulns.xss import scan_xss

__all__ = [
    "audit_jwt",
    "check_security_headers",
    "scan_lfi",
    "scan_open_redirect",
    "scan_sqli",
    "scan_ssrf",
    "scan_xss",
]
