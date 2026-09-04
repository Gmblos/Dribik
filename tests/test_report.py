"""Tests — report generation (migrated to dribik)."""
import json

from dribik.graph import add_host
from dribik.models import Finding, Graph, Scope, ScopeRule, WorkspaceMeta
from dribik.report import write_html_report, write_json_report, write_report


def _base_fixtures():
    graph = Graph()
    add_host(graph, "www.example-program.test", "manual")
    add_host(graph, "payments.example-program.test", "manual")
    meta = WorkspaceMeta(program="Example Corp BB")
    scope = Scope(
        program="Example Corp BB",
        allow=[ScopeRule(kind="domain_suffix", value="example-program.test")],
        deny=[ScopeRule(kind="host_exact", value="payments.example-program.test")],
    )
    findings = [
        Finding(
            id="F-1",
            title="In scope note",
            asset_id="host:www.example-program.test",
            operator_validated=True,
            response_diff_agreement=0.9,
        ),
        Finding(
            id="F-2",
            title="Payments host",
            asset_id="host:payments.example-program.test",
        ),
    ]
    return graph, meta, scope, findings


def test_report_splits_out_of_scope():
    graph, meta, scope, findings = _base_fixtures()
    text = write_report(meta=meta, graph=graph, scope=scope, findings=findings)
    assert "In scope note" in text
    assert "Out of scope" in text or "Out of Scope" in text
    assert "Payments host" in text
    assert findings[1].out_of_scope is True
    assert findings[0].out_of_scope is False


def test_report_executive_summary_counts():
    graph, meta, scope, findings = _base_fixtures()
    text = write_report(meta=meta, graph=graph, scope=scope, findings=findings)
    # Executive summary table present
    assert "Executive Summary" in text


def test_json_report_structure():
    graph, meta, scope, findings = _base_fixtures()
    raw = write_json_report(meta=meta, graph=graph, scope=scope, findings=findings)
    data = json.loads(raw)
    assert "findings" in data
    assert "summary" in data
    assert "meta" in data
    assert data["meta"]["program"] == "Example Corp BB"


def test_html_report_contains_severity_badge():
    graph, meta, scope, findings = _base_fixtures()
    html = write_html_report(meta=meta, graph=graph, scope=scope, findings=findings)
    assert "<html" in html
    assert "Executive Summary" in html
    # Severity stat cards present
    assert "Critical" in html
