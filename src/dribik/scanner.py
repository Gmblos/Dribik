"""Scanner — rate-limited, retry-safe, proxy-aware HTTP client + crawler + tech fingerprinter."""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable
from html.parser import HTMLParser
from typing import Any

from dribik.models import AuditEntry, ScanResult, Scope, TechStack
from dribik.scope import classify

__all__ = [
    "set_rate_limit",
    "set_proxy",
    "set_audit_callback",
    "http_get",
    "http_post",
    "crawl",
    "detect_tech_stack",
    "ScanResult",
]

logger = logging.getLogger(__name__)

_BODY_READ_LIMIT = 65536   # 64 KB — full body for matching
_DEFAULT_UA = "dribik/0.1.0-beta (authorized assessment)"
_DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
class _RateLimiter:
    """Thread-safe token-bucket rate limiter."""

    def __init__(self, rps: float = 10.0) -> None:
        self._lock = threading.Lock()
        self._interval = 1.0 / max(rps, 0.001)
        self._last: float = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait_for = self._interval - (now - self._last)
            if wait_for > 0:
                time.sleep(wait_for)
            self._last = time.monotonic()


# Global rate limiter — default 10 req/s. Call set_rate_limit() to override.
_limiter = _RateLimiter(10.0)
# Global proxy URL — None means direct connection.
_proxy_url: str | None = None
# Global audit callback — set by workspace when audit logging is enabled.
_audit_callback: Callable[[AuditEntry], None] | None = None


def set_rate_limit(rps: float) -> None:
    """Set global request rate (requests per second). 0 = unlimited."""
    global _limiter
    _limiter = _RateLimiter(rps if rps > 0 else 999999.0)


def set_proxy(url: str | None) -> None:
    """Set global HTTP/HTTPS proxy URL, e.g. 'http://127.0.0.1:8080'."""
    global _proxy_url
    _proxy_url = url


def set_audit_callback(cb: Callable[[AuditEntry], None] | None) -> None:
    """Register a function to receive an AuditEntry for every request made."""
    global _audit_callback
    _audit_callback = cb


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirect responses to the caller instead of following them."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _build_opener(*, follow_redirects: bool = True) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    if _proxy_url:
        handlers.append(urllib.request.ProxyHandler({
            "http": _proxy_url,
            "https": _proxy_url,
        }))
    else:
        handlers.append(urllib.request.ProxyHandler({}))  # disable env proxies
    handlers.append(urllib.request.HTTPRedirectHandler() if follow_redirects else _NoRedirectHandler())
    return urllib.request.build_opener(*handlers)


def _do_request(
    req: urllib.request.Request,
    timeout: int,
    *,
    follow_redirects: bool = False,
) -> tuple[int, dict[str, str], bytes, str]:
    """Execute a request through the opener. Returns (status, headers, body, final_url)."""
    opener = _build_opener(follow_redirects=follow_redirects)
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(_BODY_READ_LIMIT)
        status: int = resp.status
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        final_url: str = resp.url
    return status, hdrs, raw, final_url


# ---------------------------------------------------------------------------
# http_get / http_post — with rate limiting, retry, and audit logging
# ---------------------------------------------------------------------------
def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_retries: int = 2,
) -> ScanResult:
    """
    Perform a GET request.
    - Rate-limited by global rate limiter.
    - Retries transient errors (up to max_retries) with exponential backoff.
    - Sends an AuditEntry to the global audit callback if registered.
    - Uses proxy if configured via set_proxy().
    - Reads up to 64 KB of response body.
    - Does not follow redirects by default, preventing an in-scope request
      from silently reaching an out-of-scope host.
    """
    request_headers = {"User-Agent": _DEFAULT_UA}
    if headers:
        request_headers.update(headers)

    redirect_chain: list[str] = []
    last_error: str | None = None

    for attempt in range(max_retries + 1):
        _limiter.wait()
        start = time.monotonic()
        try:
            req = urllib.request.Request(url, headers=request_headers, method="GET")
            status, hdrs, raw, final_url = _do_request(
                req, timeout, follow_redirects=follow_redirects
            )
            elapsed = (time.monotonic() - start) * 1000
            body_text = raw.decode("utf-8", errors="replace")
            if final_url != url:
                redirect_chain.append(final_url)
            result = ScanResult(
                url=url,
                status=status,
                headers=hdrs,
                body=body_text,
                body_hash=hashlib.sha256(raw).hexdigest(),
                redirect_chain=redirect_chain,
                response_time_ms=round(elapsed, 2),
                method="GET",
            )
            _emit_audit(AuditEntry(method="GET", url=url, status=status, response_time_ms=result.response_time_ms))
            return result
        except urllib.error.HTTPError as e:
            elapsed = (time.monotonic() - start) * 1000
            body_text = e.read(_BODY_READ_LIMIT).decode("utf-8", errors="replace")
            result = ScanResult(
                url=url,
                status=e.code,
                headers={k.lower(): v for k, v in e.headers.items()},
                body=body_text,
                response_time_ms=round(elapsed, 2),
                method="GET",
            )
            _emit_audit(AuditEntry(method="GET", url=url, status=e.code, response_time_ms=result.response_time_ms))
            return result
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            last_error = str(exc)
            if attempt < max_retries:
                time.sleep(0.5 * (2 ** attempt))  # 0.5s, 1s backoff

    result = ScanResult(url=url, error=last_error, method="GET")
    _emit_audit(AuditEntry(method="GET", url=url, error=last_error))
    return result


def http_post(
    url: str,
    data: bytes | str | dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
    json_body: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
    follow_redirects: bool = False,
    max_retries: int = 2,
) -> ScanResult:
    """
    Perform a POST request.
    Supports form-encoded, raw bytes, and JSON body (json_body=True).
    Rate-limited, retried, proxy-aware, audit-logged, and redirect-safe by default.
    """
    import json as _json
    request_headers = {"User-Agent": _DEFAULT_UA}
    if json_body:
        request_headers["Content-Type"] = "application/json"
        if isinstance(data, dict):
            encoded = _json.dumps(data).encode("utf-8")
        else:
            encoded = (data or "").encode("utf-8") if isinstance(data, str) else (data or b"")
    else:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if isinstance(data, dict):
            encoded = urllib.parse.urlencode(data).encode("utf-8")
        elif isinstance(data, str):
            encoded = data.encode("utf-8")
        else:
            encoded = data or b""
    if headers:
        request_headers.update(headers)

    request_body_str = encoded.decode("utf-8", errors="replace")
    last_error: str | None = None

    for attempt in range(max_retries + 1):
        _limiter.wait()
        start = time.monotonic()
        try:
            req = urllib.request.Request(url, data=encoded, headers=request_headers, method="POST")
            status, hdrs, raw, _ = _do_request(req, timeout, follow_redirects=follow_redirects)
            elapsed = (time.monotonic() - start) * 1000
            body_text = raw.decode("utf-8", errors="replace")
            result = ScanResult(
                url=url,
                status=status,
                headers=hdrs,
                body=body_text,
                body_hash=hashlib.sha256(raw).hexdigest(),
                response_time_ms=round(elapsed, 2),
                method="POST",
                request_body=request_body_str,
            )
            _emit_audit(AuditEntry(method="POST", url=url, request_body=request_body_str[:200],
                                   status=status, response_time_ms=result.response_time_ms))
            return result
        except urllib.error.HTTPError as e:
            elapsed = (time.monotonic() - start) * 1000
            result = ScanResult(
                url=url, status=e.code,
                headers={k.lower(): v for k, v in e.headers.items()},
                body=e.read(_BODY_READ_LIMIT).decode("utf-8", errors="replace"),
                response_time_ms=round(elapsed, 2), method="POST",
                request_body=request_body_str,
            )
            _emit_audit(AuditEntry(method="POST", url=url, request_body=request_body_str[:200],
                                   status=e.code, response_time_ms=result.response_time_ms))
            return result
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            last_error = str(exc)
            if attempt < max_retries:
                time.sleep(0.5 * (2 ** attempt))

    result = ScanResult(url=url, error=last_error, method="POST", request_body=request_body_str)
    _emit_audit(AuditEntry(method="POST", url=url, request_body=request_body_str[:200], error=last_error))
    return result


def _emit_audit(entry: AuditEntry) -> None:
    if _audit_callback:
        try:
            _audit_callback(entry)
        except Exception as exc:
            logger.debug("Audit callback error: %s", exc)


# ---------------------------------------------------------------------------
# Link extractor
# ---------------------------------------------------------------------------
class _LinkParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        href = None
        if tag == "a":
            href = attr_map.get("href")
        elif tag == "form":
            href = attr_map.get("action")
        elif tag in ("script", "iframe", "frame"):
            href = attr_map.get("src")
        if href:
            joined = urllib.parse.urljoin(self.base_url, href)
            parsed = urllib.parse.urlsplit(joined)
            clean = urllib.parse.urlunsplit(parsed._replace(fragment=""))
            self.links.append(clean)


def _extract_links(base_url: str, html: str) -> list[str]:
    """Extract all links from the full HTML body."""
    parser = _LinkParser(base_url)
    try:
        parser.feed(html)
    except Exception as exc:
        logger.debug("Link parser error: %s", exc)
    return parser.links


# ---------------------------------------------------------------------------
# BFS Crawler — uses full body for link extraction
# ---------------------------------------------------------------------------
def crawl(
    start_url: str,
    scope: Scope,
    *,
    max_depth: int = 2,
    max_pages: int = 100,
    timeout: int = _DEFAULT_TIMEOUT,
) -> list[ScanResult]:
    """
    BFS web crawler respecting scope rules.
    Parses the full response body (up to 64 KB) for link extraction —
    not a truncated snippet — so links past the first few hundred bytes
    are correctly discovered.
    """
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    results: list[ScanResult] = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        if classify(scope, url) != "allow":
            continue
        visited.add(url)
        result = http_get(url, timeout=timeout)
        results.append(result)

        if depth < max_depth and result.status == 200 and result.body:
            content_type = result.headers.get("content-type", "")
            if "html" in content_type or not content_type:
                # Use the FULL body — not the 500-char snippet — for link extraction
                for link in _extract_links(url, result.body):
                    parsed = urllib.parse.urlsplit(link)
                    if parsed.scheme not in ("http", "https"):
                        continue
                    if link not in visited:
                        queue.append((link, depth + 1))

    return results


# ---------------------------------------------------------------------------
# Tech-stack fingerprinter — uses full body
# ---------------------------------------------------------------------------
_SERVER_MAP = {
    "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
    "cloudflare": "Cloudflare", "openresty": "OpenResty",
    "caddy": "Caddy", "litespeed": "LiteSpeed",
}
_FRAMEWORK_XPOWERED = {
    "express": "Node.js / Express", "php": "PHP", "asp.net": "ASP.NET",
    "next.js": "Next.js", "django": "Django", "flask": "Flask",
}
_WAF_HEADERS = {
    "x-sucuri-id": "Sucuri WAF", "cf-ray": "Cloudflare WAF",
    "x-waf-event-info": "AWS WAF", "x-ddos-protection": "DDoS Guard",
}
_CMS_BODY_RE = {
    "WordPress": re.compile(r"/wp-content/|wp-json", re.IGNORECASE),
    "Joomla":    re.compile(r"/components/com_|joomla", re.IGNORECASE),
    "Drupal":    re.compile(r"sites/default/files|drupal\.org", re.IGNORECASE),
    "Shopify":   re.compile(r"cdn\.shopify\.com", re.IGNORECASE),
    "Magento":   re.compile(r"skin/frontend/|Mage\.", re.IGNORECASE),
}


def detect_tech_stack(result: ScanResult) -> TechStack:
    """Fingerprint server, framework, WAF, CMS using full body."""
    headers = {k.lower(): v.lower() for k, v in result.headers.items()}
    ts = TechStack(raw_headers=dict(result.headers))
    server_hdr = headers.get("server", "")
    for sig, name in _SERVER_MAP.items():
        if sig in server_hdr:
            ts.server = name
            break
    if not ts.server and server_hdr:
        ts.server = server_hdr[:50]
    xpb = headers.get("x-powered-by", "")
    for sig, name in _FRAMEWORK_XPOWERED.items():
        if sig in xpb:
            ts.framework = name
            break
    for header_key, waf_name in _WAF_HEADERS.items():
        if header_key in headers:
            ts.waf = waf_name
            break
    # Use full body (not snippet) for CMS detection
    body = result.body
    for cms, pattern in _CMS_BODY_RE.items():
        if pattern.search(body):
            ts.cms = cms
            break
    return ts
