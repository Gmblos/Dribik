"""Vulnerability modules — XSS, SQLi, SSRF, LFI, Headers, JWT, OpenRedirect."""

from __future__ import annotations

from dribik.vulns.xss import scan_xss
from dribik.vulns.sqli import scan_sqli
from dribik.vulns.ssrf import scan_ssrf
from dribik.vulns.lfi import scan_lfi
from dribik.vulns.headers import check_security_headers
from dribik.vulns.jwt_audit import audit_jwt
from dribik.vulns.open_redirect import scan_open_redirect

__all__ = [
    "scan_xss",
    "scan_sqli",
    "scan_ssrf",
    "scan_lfi",
    "check_security_headers",
    "audit_jwt",
    "scan_open_redirect",
]
