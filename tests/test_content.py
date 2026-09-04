"""Tests for controlled content discovery."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from dribik.cli import main
from dribik.content import discover_content
from dribik.models import ScanResult, Scope, ScopeRule


def test_discover_content_filters_soft_404_noise() -> None:
    scope = Scope(allow=[ScopeRule(kind="domain_suffix", value="example.test")])
    baseline = ScanResult(
        url="https://example.test/.dribik-missing",
        status=404,
        body="not found",
        headers={"content-type": "text/plain", "content-length": "9"},
    )
    soft_404 = ScanResult(
        url="https://example.test/admin",
        status=404,
        body="not found",
        headers={"content-type": "text/plain", "content-length": "9"},
    )
    hit = ScanResult(
        url="https://example.test/robots.txt",
        status=200,
        body="User-agent: *",
        headers={"content-type": "text/plain", "content-length": "13"},
    )
    with mock.patch("dribik.content.http_get", side_effect=[baseline, soft_404, hit]):
        findings = discover_content(
            "https://example.test/",
            wordlist=["admin", "robots.txt"],
            scope=scope,
        )
    assert len(findings) == 1
    assert findings[0]["url"] == "https://example.test/robots.txt"
    assert findings[0]["status"] == 200


def test_discover_content_respects_scope() -> None:
    scope = Scope(allow=[ScopeRule(kind="domain_suffix", value="example.test")])
    with mock.patch("dribik.content.http_get") as http_get_mock:
        findings = discover_content(
            "https://out.example.org/",
            wordlist=["admin"],
            scope=scope,
        )
    assert findings == []
    assert not http_get_mock.called


def _allow_example_scope(ws: Path) -> None:
    (ws / "scope.yaml").write_text(
        "program: ContentTest\nallow:\n  - kind: domain_suffix\n    value: example.com\ndeny: []\n",
        encoding="utf-8",
    )


def test_cli_scan_content_requires_consent_then_reports_hits(tmp_path: Path) -> None:
    runner = CliRunner()
    ws = tmp_path / "ws"
    assert runner.invoke(main, ["init", str(ws), "--program", "ContentTest"]).exit_code == 0
    _allow_example_scope(ws)

    blocked = runner.invoke(main, ["scan", "content", str(ws), "--url", "http://example.com/"])
    assert blocked.exit_code != 0
    assert "consent" in blocked.output.lower()

    assert runner.invoke(main, [
        "consent", "grant", str(ws),
        "--target", "example.com",
        "--capability", "active_exploitation:content",
        "--operator", "tester",
    ]).exit_code == 0

    with mock.patch("dribik.cli.discover_content", return_value=[
        {
            "url": "http://example.com/admin",
            "status": 200,
            "content_type": "text/html",
            "content_length": "42",
            "body_hash": "abc123",
        }
    ]):
        result = runner.invoke(
            main,
            ["scan", "content", str(ws), "--url", "http://example.com/", "--import-graph"],
        )
    assert result.exit_code == 0, result.output
    assert "Found 1 interesting path" in result.output
    assert "http://example.com/admin" in result.output
    assert "Imported 1 endpoint" in result.output
