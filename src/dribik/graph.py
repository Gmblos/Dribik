"""Graph management — asset node merging and bundle import."""

from __future__ import annotations

from dribik.models import (
    Graph,
    Node,
    Source,
    domain_id,
    endpoint_id,
    host_id,
    js_route_id,
    param_id,
)


def _merge_node(graph: Graph, node: Node) -> Node:
    existing = graph.nodes.get(node.id)
    if existing is None:
        graph.nodes[node.id] = node
        return node
    for key, value in node.data.items():
        if key == "ips" and value:
            old = existing.data.get("ips") or []
            existing.data["ips"] = list(dict.fromkeys([*old, *value]))
        elif key == "alive" and value is not None:
            existing.data["alive"] = bool(existing.data.get("alive") or value)
        elif key == "wildcard_risk":
            existing.data[key] = bool(existing.data.get("wildcard_risk") or value)
        elif value not in (None, "", [], {}):
            existing.data[key] = value
    seen = {(s.tool, s.imported_at) for s in existing.sources}
    for source in node.sources:
        key = (source.tool, source.imported_at)
        if key not in seen:
            existing.sources.append(source)
            seen.add(key)
    return existing


def add_domain(graph: Graph, name: str, tool: str) -> Node:
    node = Node(
        id=domain_id(name),
        type="domain",
        sources=[Source(tool=tool)],
        data={"name": name.strip().lower().rstrip(".")},
    )
    return _merge_node(graph, node)


def add_host(
    graph: Graph,
    fqdn: str,
    tool: str,
    *,
    domain: str | None = None,
    alive: bool | None = None,
    ips: list[str] | None = None,
    wildcard_risk: bool = False,
) -> Node:
    fqdn_n = fqdn.strip().lower().rstrip(".")
    node = Node(
        id=host_id(fqdn_n),
        type="host",
        sources=[Source(tool=tool)],
        data={
            "fqdn": fqdn_n,
            "alive": alive,
            "ips": ips or [],
            "wildcard_risk": wildcard_risk,
        },
    )
    merged = _merge_node(graph, node)
    if domain:
        d = add_domain(graph, domain, tool)
        graph.add_edge(d.id, merged.id)
    return merged


def add_endpoint(
    graph: Graph,
    method: str,
    url: str,
    tool: str,
    *,
    host: str | None = None,
    status: int | None = None,
) -> Node:
    method_u = (method or "GET").upper()
    node = Node(
        id=endpoint_id(method_u, url),
        type="endpoint",
        sources=[Source(tool=tool)],
        data={"method": method_u, "url": url, "status": status},
    )
    merged = _merge_node(graph, node)
    if host:
        h = add_host(graph, host, tool)
        graph.add_edge(h.id, merged.id)
    return merged


def add_param(
    graph: Graph,
    endpoint: Node,
    name: str,
    location: str,
    tool: str,
) -> Node:
    node = Node(
        id=param_id(endpoint.id, location, name),
        type="param",
        sources=[Source(tool=tool)],
        data={"name": name, "in": location},
    )
    merged = _merge_node(graph, node)
    graph.add_edge(endpoint.id, merged.id)
    return merged


def add_js_route(graph: Graph, source_url: str, path: str, tool: str) -> Node:
    node = Node(
        id=js_route_id(source_url, path),
        type="js_route",
        sources=[Source(tool=tool)],
        data={"source_url": source_url, "path": path},
    )
    return _merge_node(graph, node)


def import_bundle(graph: Graph, payload: dict, tool: str | None = None) -> int:
    """Merge a JSON bundle: {tool?, hosts[], endpoints[], params[], js_routes[]}."""
    src = tool or payload.get("tool") or "import"
    before = len(graph.nodes)
    for host in payload.get("hosts") or []:
        if isinstance(host, str):
            add_host(graph, host, src)
        else:
            add_host(
                graph,
                host["fqdn"],
                src,
                domain=host.get("domain"),
                alive=host.get("alive"),
                ips=host.get("ips"),
                wildcard_risk=bool(host.get("wildcard_risk")),
            )
    for ep in payload.get("endpoints") or []:
        node = add_endpoint(
            graph,
            ep.get("method", "GET"),
            ep["url"],
            src,
            host=ep.get("host"),
            status=ep.get("status"),
        )
        for param in ep.get("params") or []:
            add_param(graph, node, param["name"], param.get("in", "query"), src)
    for param in payload.get("params") or []:
        ep = add_endpoint(
            graph,
            param.get("method", "GET"),
            param["url"],
            src,
            host=param.get("host"),
        )
        add_param(graph, ep, param["name"], param.get("in", "query"), src)
    for route in payload.get("js_routes") or []:
        add_js_route(graph, route.get("source_url", route.get("url", "")), route["path"], src)
    return len(graph.nodes) - before


def counts(graph: Graph) -> dict[str, int]:
    tally: dict[str, int] = {}
    for node in graph.nodes.values():
        tally[node.type] = tally.get(node.type, 0) + 1
    tally["total"] = len(graph.nodes)
    return tally
