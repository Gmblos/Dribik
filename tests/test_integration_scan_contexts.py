"""Integration tests for live loopback request-context probing."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from dribik.vulns.xss import scan_xss


class _EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _write(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _echo_values(self) -> str:
        parsed = urlsplit(self.path)
        values: list[str] = []

        query = parse_qs(parsed.query)
        if "q" in query:
            values.append(query["q"][0])

        header_value = self.headers.get("X-Test")
        if header_value:
            values.append(header_value)

        cookie_header = self.headers.get("Cookie", "")
        for cookie in cookie_header.split(";"):
            name, sep, raw_value = cookie.strip().partition("=")
            if name == "session" and sep:
                values.append(unquote(raw_value))

        if self.command == "POST":
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            if "application/json" in (self.headers.get("Content-Type") or ""):
                values.append(json.loads(raw_body).get("q", ""))
            else:
                values.append(parse_qs(raw_body).get("q", [""])[0])

        return " | ".join(value for value in values if value) or "empty"

    def do_GET(self) -> None:
        self._write(self._echo_values())

    def do_POST(self) -> None:
        self._write(self._echo_values())


@contextmanager
def _serve_echo() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_xss_live_loopback_hits_multiple_request_contexts() -> None:
    payload = "<svg onload=alert(1)>"
    with _serve_echo() as base_url:
        findings = scan_xss(
            f"{base_url}/reflect?q=safe",
            params=["q"],
            payloads=[payload],
            test_post=False,
            test_json=True,
            header_names=["X-Test"],
            cookie_names=["session"],
        )

    titles = {finding.title for finding in findings}
    assert any("GET query" in title for title in titles)
    assert any("JSON body" in title for title in titles)
    assert any("HTTP header" in title for title in titles)
    assert any("Cookie" in title for title in titles)
