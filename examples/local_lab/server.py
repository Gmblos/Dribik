"""A deliberately insecure, loopback-only practice server for Dribik.

It is designed for local scanner verification, not as an application template.
The default bind address (127.0.0.5) is part of the IPv4 loopback range and is
not reachable from another machine.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class PracticeHandler(BaseHTTPRequestHandler):
    """Routes intentionally selected to exercise bounded scanner modules."""

    server_version = "DribikPracticeLab/1.0"

    def log_message(self, format_: str, *args: object) -> None:
        """Keep request logging concise while the lab is being scanned."""
        print(f"[lab] {self.address_string()} - {format_ % args}")

    def _send(
        self,
        status: HTTPStatus,
        body: str = "",
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _form_data(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(raw, keep_blank_values=True)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)

        if parsed.path == "/":
            self._send(
                HTTPStatus.OK,
                """<!doctype html><title>Dribik local practice lab</title>
                <h1>Dribik local practice lab</h1>
                <p>This server is intentionally insecure and binds only to loopback.</p>
                <ul>
                  <li><a href='/search?q=hello'>Reflected input demo</a></li>
                  <li><a href='/redirect?next=/welcome'>Redirect demo</a></li>
                  <li><a href='/docs'>Documentation endpoint</a></li>
                  <li><a href='/api/status'>API status</a></li>
                </ul>""",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
            return

        if parsed.path == "/search":
            value = query.get("q", [""])[0]
            # Deliberately unescaped: this is a local XSS scanner target.
            self._send(HTTPStatus.OK, f"<h1>Search</h1><p>Results for: {value}</p>")
            return

        if parsed.path == "/redirect":
            destination = query.get("next", ["/"])[0]
            self._send(HTTPStatus.FOUND, headers={"Location": destination})
            return

        if parsed.path == "/robots.txt":
            self._send(
                HTTPStatus.OK,
                "User-agent: *\nDisallow: /admin\nAllow: /docs\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if parsed.path == "/sitemap.xml":
            self._send(
                HTTPStatus.OK,
                """<?xml version='1.0' encoding='UTF-8'?>
                <urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>
                  <url><loc>/docs</loc></url><url><loc>/api/status</loc></url>
                </urlset>""",
                content_type="application/xml; charset=utf-8",
            )
            return

        if parsed.path == "/docs":
            self._send(HTTPStatus.OK, "<h1>Practice API docs</h1><p>Local-only demo.</p>")
            return

        if parsed.path == "/api/status":
            self._send(
                HTTPStatus.OK,
                json.dumps({"status": "ok", "environment": "local-practice"}),
                content_type="application/json; charset=utf-8",
            )
            return

        if parsed.path == "/admin":
            self._send(HTTPStatus.FORBIDDEN, "<h1>Admin area</h1>")
            return

        self._send(HTTPStatus.NOT_FOUND, "<h1>Not found</h1><p>Practice-lab soft 404.</p>")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != "/search":
            self._send(HTTPStatus.NOT_FOUND, "<h1>Not found</h1>")
            return
        value = self._form_data().get("q", [""])[0]
        # Deliberately unescaped: this is a local XSS scanner target.
        self._send(HTTPStatus.OK, f"<h1>Posted search</h1><p>Results for: {value}</p>")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Dribik's loopback-only practice server.")
    parser.add_argument("--host", default="127.0.0.5", help="Loopback host (default: 127.0.0.5)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = parser.parse_args()
    if not args.host.startswith("127."):
        parser.error("this practice server may bind only to an IPv4 loopback address (127.x.x.x)")
    server = ThreadingHTTPServer((args.host, args.port), PracticeHandler)
    print(f"Dribik practice lab running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPractice lab stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
