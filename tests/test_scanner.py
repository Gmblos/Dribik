"""Tests — scanner module (rate-limiting, proxy, crawling, fingerprinting)."""

from __future__ import annotations

import time
from unittest import mock

from dribik.models import ScanResult, Scope, ScopeRule
from dribik.scanner import (
    _build_opener,
    _extract_links,
    _LinkParser,
    _RateLimiter,
    crawl,
    detect_tech_stack,
    http_get,
    http_post,
    http_request,
    set_proxy,
    set_rate_limit,
    set_request_headers,
)


def test_rate_limiter_timing() -> None:
    limiter = _RateLimiter(rps=20.0)  # 50ms interval
    t0 = time.monotonic()
    limiter.wait()
    limiter.wait()
    elapsed = time.monotonic() - t0
    # Second wait must account for interval
    assert elapsed >= 0.04


def test_set_rate_limit() -> None:
    set_rate_limit(50.0)
    set_rate_limit(0.0)  # unlimited branch


def test_set_proxy_and_build_opener() -> None:
    set_proxy("http://127.0.0.1:8080")
    opener = _build_opener(follow_redirects=True)
    assert opener is not None
    set_proxy(None)
    direct_opener = _build_opener(follow_redirects=False)
    assert direct_opener is not None


def test_set_request_headers_apply_to_http_client() -> None:
    set_request_headers({"X-Intigriti": "token-123"})
    try:
        with mock.patch("dribik.scanner._do_request", return_value=(200, {}, b"ok", "https://target.test/")) as do_request:
            with mock.patch("dribik.scanner._limiter.wait"):
                http_get("https://target.test/")
                http_post("https://target.test/", data={"q": "1"})
                http_request("PATCH", "https://target.test/", data=b"{}")
        request_headers = [call.args[0].headers for call in do_request.call_args_list]
    finally:
        set_request_headers(None)

    assert len(request_headers) == 3
    assert all(headers.get("X-intigriti") == "token-123" for headers in request_headers)


def test_link_parser_extracts_various_tags() -> None:
    html = """
    <html>
      <head>
        <script src="/static/bundle.js"></script>
      </head>
      <body>
        <a href="/about?ref=nav#section">About Us</a>
        <a href="https://external.test/page">External</a>
        <form action="/login" method="POST"></form>
        <iframe src="/embedded/frame"></iframe>
      </body>
    </html>
    """
    links = _extract_links("https://target.test/app/index.html", html)
    assert "https://target.test/static/bundle.js" in links
    assert "https://target.test/about?ref=nav" in links
    assert "https://external.test/page" in links
    assert "https://target.test/login" in links
    assert "https://target.test/embedded/frame" in links


def test_link_parser_handles_broken_markup() -> None:
    parser = _LinkParser("https://target.test")
    parser.feed("<<<invalid html>>>")
    assert isinstance(parser.links, list)


def test_crawl_respects_scope_and_depth() -> None:
    scope = Scope(allow=[ScopeRule(kind="domain_suffix", value="target.test")])

    html_root = """
    <html>
      <body>
        <a href="/page1">Page 1</a>
        <a href="https://other.test/ignored">Ignored</a>
      </body>
    </html>
    """
    html_page1 = """
    <html>
      <body>
        <a href="/page2">Page 2</a>
      </body>
    </html>
    """

    def fake_http_get(url: str, timeout: int = 10) -> ScanResult:
        if url == "https://target.test/":
            return ScanResult(url=url, status=200, body=html_root, headers={"content-type": "text/html"})
        if url == "https://target.test/page1":
            return ScanResult(url=url, status=200, body=html_page1, headers={"content-type": "text/html"})
        if url == "https://target.test/page2":
            return ScanResult(url=url, status=200, body="depth 2", headers={"content-type": "text/html"})
        return ScanResult(url=url, status=404)

    with mock.patch("dribik.scanner.http_get", side_effect=fake_http_get):
        results = crawl("https://target.test/", scope, max_depth=1, max_pages=10)

    urls = [r.url for r in results]
    assert "https://target.test/" in urls
    assert "https://target.test/page1" in urls
    assert "https://other.test/ignored" not in urls
    # Depth 1 stops before page2
    assert "https://target.test/page2" not in urls


def test_detect_tech_stack_comprehensive() -> None:
    result = ScanResult(
        url="https://app.target.test/",
        status=200,
        headers={
            "server": "nginx/1.24.0",
            "x-powered-by": "Express",
            "cf-ray": "1234567890abcdef-IAD",
        },
        body="""
        <html>
          <head>
            <link rel="stylesheet" href="/wp-content/themes/custom/style.css">
          </head>
          <body>WordPress Blog</body>
        </html>
        """,
    )
    tech = detect_tech_stack(result)
    assert tech.server == "Nginx"
    assert tech.framework == "Node.js / Express"
    assert tech.waf == "Cloudflare WAF"
    assert tech.cms == "WordPress"


def test_detect_tech_stack_fallback_server_and_drupal() -> None:
    result = ScanResult(
        url="https://drupal.target.test/",
        status=200,
        headers={"server": "CustomSecureServer/1.0"},
        body="<script src='/sites/default/files/js/script.js'></script>",
    )
    tech = detect_tech_stack(result)
    assert tech.server.lower() == "customsecureserver/1.0"
    assert tech.cms == "Drupal"
