"""Tests — asset graph (migrated to dribik)."""
from dribik.graph import add_host, import_bundle
from dribik.models import Graph


def test_host_dedupe_keeps_sources():
    graph = Graph()
    add_host(graph, "www.example-program.test", "subfinder")
    add_host(graph, "WWW.example-program.test", "amass", ips=["192.0.2.10"])
    assert len([n for n in graph.nodes.values() if n.type == "host"]) == 1
    node = graph.nodes["host:www.example-program.test"]
    tools = {s.tool for s in node.sources}
    assert tools == {"subfinder", "amass"}
    assert node.data["ips"] == ["192.0.2.10"]


def test_import_bundle_endpoints_and_params():
    graph = Graph()
    import_bundle(
        graph,
        {
            "tool": "gau",
            "endpoints": [
                {
                    "method": "get",
                    "url": "https://api.example-program.test/v1/users?b=2&a=1",
                    "host": "api.example-program.test",
                    "params": [{"name": "q", "in": "query"}],
                }
            ],
        },
    )
    endpoints = [n for n in graph.nodes.values() if n.type == "endpoint"]
    assert len(endpoints) == 1
    params = [n for n in graph.nodes.values() if n.type == "param"]
    assert len(params) == 1
