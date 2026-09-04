from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from dribik.cli import main
from dribik.models import ScanResult
from dribik.raw_http import parse_raw_request, replay_raw_request


def test_parse_raw_request_builds_absolute_url_and_strips_transport_headers() -> None:
    request = parse_raw_request(
        b"POST /api/items?draft=1 HTTP/1.1\r\nHost: api.example.test\r\n"
        b"Authorization: Bearer test\r\nContent-Length: 7\r\n\r\nname=ok"
    )
    assert request.method == "POST"
    assert request.url() == "https://api.example.test/api/items?draft=1"
    assert request.replay_headers() == {"authorization": "Bearer test"}
    assert request.body == b"name=ok"


def test_parse_raw_request_rejects_ambiguous_input() -> None:
    for raw in (b"GET / HTTP/1.1\r\nHost: example.test", b"GET relative HTTP/1.1\nHost: x\n\n"):
        try:
            request = parse_raw_request(raw)
            request.url()
        except ValueError:
            continue
        raise AssertionError("invalid raw request was accepted")


def test_replay_passes_method_body_and_safe_headers() -> None:
    request = parse_raw_request(b"PATCH /v1 HTTP/1.1\nHost: api.example.test\nX-Test: yes\n\nbody")
    with mock.patch("dribik.raw_http.http_request", return_value=ScanResult(url="https://api.example.test/v1", status=200)) as call:
        replay_raw_request(request)
    assert call.call_args.kwargs["data"] == b"body"
    assert call.call_args.kwargs["headers"] == {"x-test": "yes"}
    assert call.call_args.args[:2] == ("PATCH", "https://api.example.test/v1")


def test_cli_replay_requires_scope_and_consent_then_replays(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    request_file = tmp_path / "request.txt"
    request_file.write_text("GET /health HTTP/1.1\nHost: example.com\n\n", encoding="utf-8")
    runner = CliRunner()
    assert runner.invoke(main, ["init", str(workspace), "--program", "test"]).exit_code == 0
    (workspace / "scope.yaml").write_text(
        "program: test\nallow:\n  - kind: domain_suffix\n    value: example.com\ndeny: []\n",
        encoding="utf-8",
    )
    assert runner.invoke(main, [
        "consent", "grant", str(workspace), "--target", "example.com", "--capability", "active_exploitation",
        "--operator", "tester",
    ]).exit_code == 0
    with mock.patch("dribik.cli.replay_raw_request", return_value=ScanResult(url="https://example.com/health", status=200)):
        result = runner.invoke(main, ["request", "replay", str(workspace), "--file", str(request_file)])
    assert result.exit_code == 0, result.output
    assert "HTTP 200" in result.output
