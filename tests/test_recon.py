"""Tests — recon module (migrated to dribik)."""
from dribik.graph import add_endpoint, add_host, add_js_route
from dribik.models import Graph
from dribik.recon import extract_tokens, recon_plan


def test_recon_plan_lists_unresolved():
    graph = Graph()
    add_host(graph, "live.example-program.test", "x", ips=["192.0.2.1"], alive=True)
    add_host(graph, "ghost.example-program.test", "x")
    plan = recon_plan(graph)
    assert "ghost.example-program.test" in plan["unresolved_needs_operator_review"]
    assert "live.example-program.test" in plan["live_or_resolved"]


def test_tokens_from_paths():
    graph = Graph()
    add_endpoint(graph, "GET", "https://www.example-program.test/login", "x")
    add_js_route(graph, "https://www.example-program.test/app.js", "/api/internal/health", "x")
    tokens = extract_tokens(graph)
    assert "login" in tokens
    assert "health" in tokens


def test_recon_plan_wildcard_flagged():
    graph = Graph()
    add_host(graph, "wild.example.test", "x", wildcard_risk=True, ips=["1.2.3.4"])
    plan = recon_plan(graph)
    assert "wild.example.test" in plan["wildcard_risk_hosts"]
