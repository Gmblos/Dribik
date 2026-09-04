"""Subdomain enumeration — DNS brute-force and takeover detection."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Dangling CNAME fingerprints for common services
_TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "GitHub Pages": ["there isn't a github pages site here", "for root domain"],
    "Heroku": ["no such app", "herokucdn.com/error-pages/no-such-app.html"],
    "Netlify": ["not found - request id"],
    "AWS S3": ["nosuchbucket", "the specified bucket does not exist"],
    "Fastly": ["fastly error: unknown domain"],
    "Shopify": ["sorry, this shop is currently unavailable"],
    "Tumblr": ["whatever you were looking for doesn't currently exist at this address"],
    "Ghost": ["the thing you were looking for is no longer here"],
    "Cargo": ["if you're moving your domain away from cargo"],
    "Zendesk": ["help center closed"],
}


def _resolve(fqdn: str) -> tuple[str, list[str]]:
    """Resolve FQDN → list of IPs (empty = not resolved)."""
    try:
        infos = socket.getaddrinfo(fqdn, None)
        ips = list({i[4][0] for i in infos})
        return fqdn, ips
    except socket.gaierror:
        return fqdn, []


def _load_wordlist(name: str) -> list[str]:
    """Load a built-in payload wordlist by filename."""
    payload_dir = Path(__file__).parent / "payloads"
    p = payload_dir / name
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    return []


def enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    max_workers: int = 50,
) -> list[dict]:
    """
    DNS brute-force subdomain enumeration.

    Args:
        domain: Base domain to enumerate (e.g. "example.com").
        wordlist: List of subdomain prefixes. If None, loads the built-in list.
        max_workers: Thread concurrency for DNS resolution.

    Returns:
        List of dicts: {"fqdn": str, "ips": list[str], "alive": bool}
    """
    if wordlist is None:
        wordlist = _load_wordlist("subdomains.txt")

    candidates = [f"{prefix.strip()}.{domain}" for prefix in wordlist if prefix.strip()]
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_resolve, fqdn): fqdn for fqdn in candidates}
        for future in as_completed(futures):
            fqdn, ips = future.result()
            if ips:
                results.append({"fqdn": fqdn, "ips": ips, "alive": True})

    return sorted(results, key=lambda r: r["fqdn"])


def check_subdomain_takeover(fqdn: str, timeout: int = 8) -> dict:
    """
    Check if a subdomain is potentially vulnerable to takeover.

    Resolves the FQDN; if it resolves but the HTTP response body matches
    a known dangling-CNAME fingerprint, flags it as at-risk.

    Returns:
        {"fqdn": str, "vulnerable": bool, "service": str, "note": str}
    """
    import urllib.request

    result = {
        "fqdn": fqdn,
        "vulnerable": False,
        "service": "",
        "note": "",
    }
    _, ips = _resolve(fqdn)
    if not ips:
        result["note"] = "Does not resolve — possible dangling DNS record"
        result["vulnerable"] = True
        return result

    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{fqdn}/"
            req = urllib.request.Request(url, headers={"User-Agent": "dribik/0.0.2-beta"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace").lower()
            for service, markers in _TAKEOVER_FINGERPRINTS.items():
                for marker in markers:
                    if marker.lower() in body:
                        result["vulnerable"] = True
                        result["service"] = service
                        result["note"] = f"Matched takeover fingerprint for {service}"
                        return result
            break
        except Exception:
            continue

    return result
