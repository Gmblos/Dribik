"""Recon — passive-first intelligence: graph token extraction, crt.sh, robots/sitemap."""

from __future__ import annotations

import urllib.request
import urllib.error
import json
import re
from xml.etree import ElementTree

from dribik.models import Graph


# ---------------------------------------------------------------------------
# Existing passive helpers
# ---------------------------------------------------------------------------
_SKIP = {"", "/", ".", ".."}


def extract_tokens(graph: Graph) -> list[str]:
    """Unique path segments and parameter names already in the graph."""
    tokens: set[str] = set()
    for node in graph.nodes.values():
        if node.type == "endpoint":
            url = node.data.get("url") or ""
            path = url.split("://", 1)[-1]
            if "/" in path:
                path = "/" + path.split("/", 1)[1]
            for part in path.split("/"):
                piece = part.split("?")[0].strip()
                if piece and piece not in _SKIP and not piece.startswith("{"):
                    tokens.add(piece)
        elif node.type == "param":
            name = (node.data.get("name") or "").strip()
            if name:
                tokens.add(name)
        elif node.type == "js_route":
            path = node.data.get("path") or ""
            for part in path.split("/"):
                piece = part.strip()
                if piece and piece not in _SKIP:
                    tokens.add(piece)
    return sorted(tokens)


def recon_plan(graph: Graph) -> dict:
    """Passive-first plan: unresolved hosts need operator review (no brute-force)."""
    unresolved: list[str] = []
    wildcard: list[str] = []
    live: list[str] = []
    for node in graph.nodes.values():
        if node.type != "host":
            continue
        fqdn = node.data.get("fqdn", node.id)
        if node.data.get("wildcard_risk"):
            wildcard.append(fqdn)
        ips = node.data.get("ips") or []
        alive = node.data.get("alive")
        if alive or ips:
            live.append(fqdn)
        else:
            unresolved.append(fqdn)
    return {
        "policy": "passive_first",
        "live_or_resolved": sorted(live),
        "unresolved_needs_operator_review": sorted(unresolved),
        "wildcard_risk_hosts": sorted(wildcard),
        "notes": (
            "Unresolved hosts are listed for human review. "
            "Dribik 0.0.2-beta does not brute-force DNS labels or probe HTTP without consent."
        ),
    }


# ---------------------------------------------------------------------------
# NEW: crt.sh certificate transparency passive DNS
# ---------------------------------------------------------------------------
def passive_dns_crtsh(domain: str, timeout: int = 10) -> list[str]:
    """
    Query crt.sh certificate transparency logs for subdomains of *domain*.
    Returns a sorted, deduplicated list of discovered FQDNs.
    Purely passive — no direct contact with the target.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains: set[str] = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dribik/0.0.2-beta"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line.lower())
    except Exception:
        pass
    return sorted(subdomains)


# ---------------------------------------------------------------------------
# NEW: robots.txt + sitemap.xml URL harvester
# ---------------------------------------------------------------------------
_SITEMAP_RE = re.compile(r"Sitemap:\s*(\S+)", re.IGNORECASE)
_DISALLOW_RE = re.compile(r"Disallow:\s*(\S+)", re.IGNORECASE)


def fetch_robots(base_url: str, timeout: int = 10) -> dict:
    """
    Fetch and parse robots.txt from *base_url*.
    Returns {"sitemap_urls": [...], "disallowed_paths": [...], "raw": "..."}.
    """
    base_url = base_url.rstrip("/")
    robots_url = f"{base_url}/robots.txt"
    result: dict = {"sitemap_urls": [], "disallowed_paths": [], "raw": ""}
    try:
        req = urllib.request.Request(robots_url, headers={"User-Agent": "dribik/0.0.2-beta"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        result["raw"] = raw
        result["sitemap_urls"] = _SITEMAP_RE.findall(raw)
        result["disallowed_paths"] = [
            p for p in _DISALLOW_RE.findall(raw) if p and p != "/"
        ]
    except Exception:
        pass
    return result


def fetch_sitemap(sitemap_url: str, timeout: int = 10) -> list[str]:
    """
    Fetch and parse a sitemap XML, returning all <loc> URLs found.
    Follows sitemap index files one level deep.
    """
    urls: list[str] = []
    try:
        req = urllib.request.Request(sitemap_url, headers={"User-Agent": "dribik/0.0.2-beta"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        root = ElementTree.fromstring(raw)
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        # Sitemap index
        for loc in root.findall(".//sm:sitemap/sm:loc", ns):
            child_urls = fetch_sitemap(loc.text or "", timeout=timeout)
            urls.extend(child_urls)
        # Regular sitemap
        for loc in root.findall(".//sm:url/sm:loc", ns):
            if loc.text:
                urls.append(loc.text.strip())
    except Exception:
        pass
    return urls
