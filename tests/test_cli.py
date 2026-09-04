"""Tests — CLI commands (migrated to dribik)."""
from pathlib import Path

from click.testing import CliRunner

from dribik.cli import main


def _allow_example_scope(ws: Path) -> None:
    (ws / "scope.yaml").write_text(
        "program: ConsentTest2\nallow:\n  - kind: domain_suffix\n    value: example.com\ndeny: []\n",
        encoding="utf-8",
    )


def test_cli_init_and_status(tmp_path: Path):
    runner = CliRunner()
    ws = tmp_path / "ws"
    result = runner.invoke(main, ["init", str(ws), "--program", "Demo"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(main, ["graph", "status", str(ws)])
    assert result.exit_code == 0
    assert '"total": 0' in result.output


def test_cli_doctor_reports_healthy_workspace(tmp_path: Path):
    runner = CliRunner()
    ws = tmp_path / "doctor"
    runner.invoke(main, ["init", str(ws), "--program", "Demo"])
    result = runner.invoke(main, ["doctor", str(ws)])
    assert result.exit_code == 0, result.output
    assert '"dribik.yaml": "ok"' in result.output


def test_cli_scope_check(tmp_path: Path):
    runner = CliRunner()
    ws = tmp_path / "ws2"
    runner.invoke(main, ["init", str(ws), "--program", "ScopeTest"])
    # Without loading a scope file, all assets are unknown
    result = runner.invoke(main, ["scope", "check", str(ws), "example.com"])
    assert result.exit_code == 0
    assert "UNKNOWN" in result.output.upper() or "unknown" in result.output.lower()


def test_cli_scan_blocked_without_consent(tmp_path: Path):
    """All scan commands must refuse to run without recorded consent."""
    runner = CliRunner()
    ws = tmp_path / "ws3"
    runner.invoke(main, ["init", str(ws), "--program", "ConsentTest"])
    _allow_example_scope(ws)

    for cmd_args in [
        ["scan", "xss", str(ws), "--url", "http://example.com/"],
        ["scan", "sqli", str(ws), "--url", "http://example.com/"],
        ["scan", "ssrf", str(ws), "--url", "http://example.com/"],
        ["scan", "lfi", str(ws), "--url", "http://example.com/"],
        ["scan", "headers", str(ws), "--url", "http://example.com/"],
        ["scan", "redirect", str(ws), "--url", "http://example.com/"],
        ["scan", "crawl", str(ws), "--url", "http://example.com/"],
        ["scan", "tech", str(ws), "--url", "http://example.com/"],
    ]:
        result = runner.invoke(main, cmd_args)
        assert result.exit_code != 0, (
            f"Expected non-zero exit without consent for: {cmd_args}\n"
            f"Got: {result.output}"
        )
        assert "consent" in result.output.lower(), (
            f"Expected 'consent' in error for: {cmd_args}\nGot: {result.output}"
        )


def test_cli_scan_allowed_after_consent(tmp_path: Path):
    """After granting consent, scan commands should proceed past the consent gate."""
    from unittest import mock

    from dribik.models import ScanResult

    runner = CliRunner()
    ws = tmp_path / "ws4"
    runner.invoke(main, ["init", str(ws), "--program", "ConsentTest2"])
    _allow_example_scope(ws)
    # Grant consent
    result = runner.invoke(main, [
        "consent", "grant", str(ws),
        "--target", "example.com",
        "--capability", "active_exploitation",
        "--operator", "tester",
    ])
    assert result.exit_code == 0, result.output

    # Patch http_get so no real network call is made.
    # The test only verifies the consent gate is cleared — not that XSS was found.
    clean_result = ScanResult(url="http://example.com/", status=200, body="hello")
    with mock.patch("dribik.vulns.xss.http_get", return_value=clean_result):
        result = runner.invoke(main, ["scan", "xss", str(ws), "--url", "http://example.com/", "--no-post"])
    # Should NOT contain a consent error
    assert "No valid consent" not in result.output
    # Should have reached the scanning stage
    assert "Scanning XSS" in result.output


def test_cli_scan_blocked_when_target_is_not_in_scope(tmp_path: Path):
    runner = CliRunner()
    ws = tmp_path / "ws-scope"
    runner.invoke(main, ["init", str(ws), "--program", "ScopeTest"])
    result = runner.invoke(main, [
        "consent", "grant", str(ws), "--target", "example.com",
        "--capability", "active_exploitation", "--operator", "tester",
    ])
    assert result.exit_code == 0
    result = runner.invoke(main, ["scan", "headers", str(ws), "--url", "https://example.com/"])
    assert result.exit_code != 0
    assert "allowed scope" in result.output


def test_cli_findings_score(tmp_path: Path):
    runner = CliRunner()
    ws = tmp_path / "ws5"
    runner.invoke(main, ["init", str(ws), "--program", "ScoreTest"])
    # Score empty findings list should succeed
    result = runner.invoke(main, ["findings", "score", str(ws)])
    assert result.exit_code == 0
