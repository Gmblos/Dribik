"""Tests — collection export (migrated to dribik)."""
from dribik.collection import to_postman
from dribik.graph import add_endpoint, add_host
from dribik.models import Graph, Scope, ScopeRule


def test_collection_omits_denied_hosts():
    graph = Graph()
    add_host(graph, "www.example-program.test", "manual")
    add_endpoint(
        graph,
        "GET",
        "https://www.example-program.test/login",
        "manual",
        host="www.example-program.test",
    )
    add_endpoint(
        graph,
        "POST",
        "https://payments.example-program.test/charge",
        "manual",
        host="payments.example-program.test",
    )
    scope = Scope(
        allow=[ScopeRule(kind="domain_suffix", value="example-program.test")],
        deny=[ScopeRule(kind="host_exact", value="payments.example-program.test")],
    )
    col = to_postman(graph, scope, "demo")
    urls = [item["request"]["url"] for item in col["item"]]
    assert urls == ["https://www.example-program.test/login"]


def test_collection_postman_schema():
    graph = Graph()
    scope = Scope()
    col = to_postman(graph, scope, "empty-test")
    assert col["info"]["schema"] == "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    assert col["item"] == []
