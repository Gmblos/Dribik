"""Collection — Postman-compatible export."""

from __future__ import annotations

from typing import Any

from dribik.models import Graph, Scope
from dribik.scope import classify


def to_postman(graph: Graph, scope: Scope, name: str) -> dict[str, Any]:
    items = []
    skipped = 0
    for node in sorted(graph.nodes.values(), key=lambda n: n.id):
        if node.type != "endpoint":
            continue
        url = node.data.get("url") or ""
        if classify(scope, url) != "allow":
            skipped += 1
            continue
        method = node.data.get("method") or "GET"
        items.append(
            {
                "name": f"{method} {url}",
                "request": {
                    "method": method,
                    "header": [],
                    "url": url,
                    "description": "Exported from Dribik graph; in-scope only.",
                },
            }
        )
    return {
        "info": {
            "name": name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": f"In-scope endpoints only. Omitted out-of-scope: {skipped}.",
        },
        "item": items,
    }
