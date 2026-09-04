"""Parse and safely replay operator-supplied raw HTTP/1.1 requests."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from dribik.models import ScanResult
from dribik.scanner import http_request

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_HOP_BY_HOP_HEADERS = {
    "connection", "content-length", "host", "keep-alive", "proxy-connection",
    "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
}


@dataclass(frozen=True)
class RawRequest:
    """A validated HTTP request suitable for a deliberate, authorized replay."""

    method: str
    target: str
    headers: dict[str, str]
    body: bytes = b""

    def url(self, scheme: str = "https") -> str:
        """Return an absolute URL, using Host for origin-form request targets."""
        if scheme not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        parsed = urlsplit(self.target)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if not self.target.startswith("/"):
            raise ValueError("request target must be an absolute URL or start with '/'")
        host = self.headers.get("host", "").strip()
        if not host or any(char.isspace() for char in host):
            raise ValueError("raw request needs a valid Host header")
        return f"{scheme}://{host}{self.target}"

    def replay_headers(self) -> dict[str, str]:
        """Remove transport-managed headers before replaying the request."""
        return {key: value for key, value in self.headers.items() if key.lower() not in _HOP_BY_HOP_HEADERS}


def parse_raw_request(raw: str | bytes) -> RawRequest:
    """Parse one HTTP/1.x request without accepting ambiguous or injected headers."""
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if not raw_bytes or len(raw_bytes) > _MAX_REQUEST_BYTES:
        raise ValueError("raw request must be between 1 byte and 2 MiB")
    normalized = raw_bytes.replace(b"\r\n", b"\n")
    head, separator, body = normalized.partition(b"\n\n")
    if not separator:
        raise ValueError("raw request must contain a blank line between headers and body")
    try:
        lines = head.decode("iso-8859-1").split("\n")
    except UnicodeDecodeError as exc:
        raise ValueError("request headers are not valid HTTP text") from exc
    if not lines or len(lines[0].split()) != 3:
        raise ValueError("request line must be: METHOD target HTTP/1.0 or HTTP/1.1")
    method, target, version = lines[0].split()
    if not method.isalpha() or version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("unsupported HTTP request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise ValueError("invalid HTTP header line")
        name, value = line.split(":", 1)
        if not name or any(char not in "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for char in name):
            raise ValueError(f"invalid HTTP header name: {name!r}")
        if "\r" in value or "\n" in value:
            raise ValueError("invalid HTTP header value")
        headers[name.lower()] = value.strip()
    return RawRequest(method=method.upper(), target=target, headers=headers, body=body)


def replay_raw_request(request: RawRequest, *, scheme: str = "https", timeout: int = 10,
                       follow_redirects: bool = False) -> ScanResult:
    """Replay a parsed request through Dribik's rate-limited audited HTTP client."""
    return http_request(
        request.method, request.url(scheme), data=request.body, headers=request.replay_headers(),
        timeout=timeout, follow_redirects=follow_redirects,
    )
