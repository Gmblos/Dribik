"""Controlled content discovery for authorized web assessments."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from dribik.models import Scope
from dribik.scanner import http_get
from dribik.scope import classify

_DEFAULT_WORDLIST = "content.txt"
_INTERESTING_STATUSES = {200, 204, 301, 302, 303, 307, 308, 401, 403}


def _load_wordlist(name: str) -> list[str]:
    payload_dir = Path(__file__).parent / "payloads"
    path = payload_dir / name
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _normalize_base_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("provide an absolute HTTP(S) URL")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))


def _candidate_url(base_url: str, path: str) -> str:
    path = path.strip()
    if not path:
        raise ValueError("wordlist entries must not be empty")
    if path.startswith(("http://", "https://")):
        raise ValueError("wordlist entries must be relative paths")
    joined = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    parsed = urlsplit(joined)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def discover_content(
    base_url: str,
    *,
    wordlist: list[str] | None = None,
    scope: Scope | None = None,
    timeout: int = 10,
    max_candidates: int = 250,
) -> list[dict[str, object]]:
    """
    Probe a curated list of common paths and return only responses that differ
    from a soft-404 baseline.
    """
    base_url = _normalize_base_url(base_url)
    if scope and classify(scope, base_url) != "allow":
        return []
    if wordlist is None:
        wordlist = _load_wordlist(_DEFAULT_WORDLIST)
    candidates = [entry.strip() for entry in wordlist if entry.strip()][:max_candidates]
    if not candidates:
        return []

    baseline_path = f"/.dribik-missing-{uuid.uuid4().hex}"
    baseline = http_get(
        urljoin(base_url.rstrip("/") + "/", baseline_path.lstrip("/")),
        timeout=timeout,
        follow_redirects=False,
    )
    baseline_hash = baseline.body_hash or hashlib.sha256((baseline.body or "").encode("utf-8")).hexdigest()
    baseline_length = baseline.headers.get("content-length", "") or ""
    baseline_signature = None if baseline.error else (baseline.status, baseline_hash, baseline_length)

    findings: list[dict[str, object]] = []
    for entry in candidates:
        candidate = _candidate_url(base_url, entry)
        if scope and classify(scope, candidate) != "allow":
            continue
        result = http_get(candidate, timeout=timeout, follow_redirects=False)
        if result.error or result.status is None:
            continue
        body_hash = result.body_hash or hashlib.sha256((result.body or "").encode("utf-8")).hexdigest()
        content_length = result.headers.get("content-length", "") or ""
        signature = (result.status, body_hash, content_length)
        if baseline_signature is not None and signature == baseline_signature:
            continue
        if result.status not in _INTERESTING_STATUSES and body_hash == baseline_hash:
            continue
        findings.append(
            {
                "url": candidate,
                "status": result.status,
                "content_type": result.headers.get("content-type", ""),
                "content_length": content_length,
                "body_hash": body_hash,
            }
        )
    return findings
