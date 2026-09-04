"""Dribik CLI — authorized web pentesting workspace."""

from __future__ import annotations

import json
from pathlib import Path
from typing import get_args

import click
import yaml

from dribik import __version__
from dribik.collection import to_postman
from dribik.consent import grant
from dribik.consent import require as consent_require
from dribik.graph import add_endpoint, add_host, counts, import_bundle
from dribik.models import Capability, FindingsFile, Scope
from dribik.recon import extract_tokens, fetch_robots, fetch_sitemap, passive_dns_crtsh, recon_plan
from dribik.report import write_html_report, write_json_report, write_report
from dribik.scope import classify
from dribik.scoring import apply_scores, risk_matrix
from dribik.workspace import Workspace

# All valid Capability literals — used for click.Choice
_ALL_CAPABILITIES = list(get_args(Capability))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------
@click.group()
@click.version_option(__version__, prog_name="dribik")
@click.option("--rate", default=10.0, show_default=True,
              help="Max requests per second (across all scan commands).", type=float)
@click.option("--proxy", default=None,
              help="HTTP/HTTPS proxy URL, e.g. http://127.0.0.1:8080 (Burp/ZAP).", type=str)
@click.pass_context
def main(ctx: click.Context, rate: float, proxy: str | None) -> None:
    """Dribik — authorized web pentesting workspace (0.0.2-beta)."""
    from dribik.scanner import set_proxy, set_rate_limit
    set_rate_limit(rate)
    if proxy:
        set_proxy(proxy)
    ctx.ensure_object(dict)
    ctx.obj["rate"] = rate
    ctx.obj["proxy"] = proxy


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------
@main.command("init")
@click.argument("path", type=click.Path(path_type=Path))
@click.option("--program", required=True, help="Program or engagement name")
def init_cmd(path: Path, program: str) -> None:
    """Initialize a new Dribik workspace."""
    ws = Workspace(path)
    ws.create(program)
    click.echo(f"✓ Initialized Dribik workspace at {path.resolve()}")


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------
@main.group()
def scope() -> None:
    """Program scope / Rules of Engagement."""


@scope.command("load")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--file", "file_", required=True, type=click.Path(path_type=Path, exists=True))
def scope_load(workspace: Path, file_: Path) -> None:
    """Load scope rules from a YAML file."""
    ws = Workspace(workspace)
    data = yaml.safe_load(file_.read_text(encoding="utf-8"))
    ws.save_scope(Scope.model_validate(data))
    click.echo("✓ Scope loaded.")


@scope.command("check")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.argument("asset")
def scope_check(workspace: Path, asset: str) -> None:
    """Check whether ASSET is in-scope (allow/deny/unknown)."""
    ws = Workspace(workspace)
    result = classify(ws.load_scope(), asset)
    color = {"allow": "green", "deny": "red", "unknown": "yellow"}.get(result, "white")
    click.echo(click.style(result.upper(), fg=color, bold=True) + f"  {asset}")


# ---------------------------------------------------------------------------
# consent
# ---------------------------------------------------------------------------
@main.group()
def consent() -> None:
    """Per-target capability consent."""


@consent.command("grant")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--target", required=True)
@click.option("--capability", required=True, type=click.Choice(_ALL_CAPABILITIES, case_sensitive=False))
@click.option("--operator", required=True)
@click.option("--note", default="")
def consent_grant(workspace: Path, target: str, capability: str, operator: str, note: str) -> None:
    """Record written consent for a capability on a target."""
    ws = Workspace(workspace)
    log = ws.load_consent()
    record = grant(log, target=target, capability=capability, operator=operator, note=note)  # type: ignore[arg-type]
    ws.save_consent(log)
    click.echo(f"✓ Granted {record.capability} on {record.target} at {record.granted_at}")


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------
@main.group()
def graph() -> None:
    """Unified asset graph."""


@graph.command("import")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--file", "file_", required=True, type=click.Path(path_type=Path, exists=True))
def graph_import(workspace: Path, file_: Path) -> None:
    """Merge a JSON bundle into the asset graph."""
    ws = Workspace(workspace)
    g = ws.load_graph()
    payload = json.loads(file_.read_text(encoding="utf-8"))
    added = import_bundle(g, payload)
    ws.save_graph(g)
    click.echo(f"✓ Merged bundle — new nodes: {added} | total: {len(g.nodes)}")


@graph.command("add")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--host")
@click.option("--url")
@click.option("--method", default="GET")
@click.option("--tool", default="manual")
def graph_add(workspace: Path, host: str | None, url: str | None, method: str, tool: str) -> None:
    """Manually add a host or endpoint to the graph."""
    ws = Workspace(workspace)
    g = ws.load_graph()
    if host:
        add_host(g, host, tool)
    if url:
        add_endpoint(g, method, url, tool, host=host)
    if not host and not url:
        raise click.UsageError("Provide --host and/or --url")
    ws.save_graph(g)
    click.echo("✓ Graph updated.")


@graph.command("status")
@click.argument("workspace", type=click.Path(path_type=Path))
def graph_status(workspace: Path) -> None:
    """Print a node-count summary of the asset graph."""
    ws = Workspace(workspace)
    click.echo(json.dumps(counts(ws.load_graph()), indent=2))


# ---------------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------------
@main.group()
def recon() -> None:
    """Passive-first reconnaissance."""


@recon.command("plan")
@click.argument("workspace", type=click.Path(path_type=Path))
def recon_plan_cmd(workspace: Path) -> None:
    """Print a passive recon plan based on current graph state."""
    ws = Workspace(workspace)
    click.echo(json.dumps(recon_plan(ws.load_graph()), indent=2))


@recon.command("tokens")
@click.argument("workspace", type=click.Path(path_type=Path))
def recon_tokens_cmd(workspace: Path) -> None:
    """List path-segment and parameter tokens from the graph."""
    ws = Workspace(workspace)
    for token in extract_tokens(ws.load_graph()):
        click.echo(token)


@recon.command("passive-dns")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--domain", required=True, help="Domain to query on crt.sh")
@click.option("--import-graph", is_flag=True, default=False, help="Add discovered hosts to asset graph")
def recon_passive_dns(workspace: Path, domain: str, import_graph: bool) -> None:
    """Query crt.sh certificate transparency logs for subdomains (passive, no direct target contact)."""
    click.echo(f"Querying crt.sh for *.{domain} …")
    subdomains = passive_dns_crtsh(domain)
    if not subdomains:
        click.echo("No subdomains found.")
        return
    click.echo(f"Found {len(subdomains)} subdomain(s):")
    for sd in subdomains:
        click.echo(f"  {sd}")
    if import_graph:
        ws = Workspace(workspace)
        g = ws.load_graph()
        for sd in subdomains:
            add_host(g, sd, "crt.sh", domain=domain)
        ws.save_graph(g)
        click.echo(f"✓ Imported {len(subdomains)} host(s) into graph.")


@recon.command("robots")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Base URL of the target (e.g. https://example.com)")
@click.option("--import-graph", is_flag=True, default=False, help="Add discovered URLs to asset graph")
def recon_robots_cmd(workspace: Path, url: str, import_graph: bool) -> None:
    """Fetch and parse robots.txt and sitemap.xml."""
    _require_authorized_target(workspace, url)
    click.echo(f"Fetching {url}/robots.txt …")
    robots = fetch_robots(url)
    click.echo(f"  Disallowed paths: {len(robots['disallowed_paths'])}")
    for p in robots["disallowed_paths"]:
        click.echo(f"    {p}")
    click.echo(f"  Sitemaps: {len(robots['sitemap_urls'])}")
    all_sitemap_urls: list[str] = []
    for sm_url in robots["sitemap_urls"]:
        click.echo(f"  Fetching sitemap: {sm_url} …")
        sitemap_urls = fetch_sitemap(sm_url)
        all_sitemap_urls.extend(sitemap_urls)
        click.echo(f"    Found {len(sitemap_urls)} URL(s)")
    if import_graph and all_sitemap_urls:
        ws = Workspace(workspace)
        g = ws.load_graph()
        for su in all_sitemap_urls:
            add_endpoint(g, "GET", su, "sitemap")
        ws.save_graph(g)
        click.echo(f"✓ Imported {len(all_sitemap_urls)} endpoint(s) into graph.")


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
@main.group()
def findings() -> None:
    """Imported and scanned findings."""


@findings.command("import")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--file", "file_", required=True, type=click.Path(path_type=Path, exists=True))
def findings_import(workspace: Path, file_: Path) -> None:
    """Import findings from a JSON file."""
    ws = Workspace(workspace)
    incoming = FindingsFile.model_validate_json(file_.read_text(encoding="utf-8"))
    apply_scores(incoming.findings)
    existing = ws.load_findings()
    by_id = {f.id: f for f in existing.findings}
    for finding in incoming.findings:
        by_id[finding.id] = finding
    existing.findings = list(by_id.values())
    ws.save_findings(existing)
    click.echo(f"✓ Findings stored: {len(existing.findings)}")


@findings.command("score")
@click.argument("workspace", type=click.Path(path_type=Path))
def findings_score(workspace: Path) -> None:
    """Re-score all findings and print confidence values."""
    ws = Workspace(workspace)
    bundle = ws.load_findings()
    apply_scores(bundle.findings)
    ws.save_findings(bundle)
    for finding in bundle.findings:
        click.echo(f"{finding.id}\t{finding.severity}\t{finding.confidence:.4f}")


@findings.command("risk-matrix")
@click.argument("workspace", type=click.Path(path_type=Path))
def findings_risk_matrix(workspace: Path) -> None:
    """Print a severity × confidence risk matrix."""
    ws = Workspace(workspace)
    bundle = ws.load_findings()
    apply_scores(bundle.findings)
    matrix = risk_matrix(bundle.findings)
    click.echo(json.dumps(matrix, indent=2))


# ---------------------------------------------------------------------------
# Consent enforcement helpers
# ---------------------------------------------------------------------------
def _require_active_consent(workspace: Path, target: str, capability: str = "active_exploitation") -> None:
    """
    Load the consent log and raise click.UsageError if the required capability
    has not been granted for *target*.

    Accepts either specific sub-capabilities (e.g. 'active_exploitation:sqli')
    or the blanket 'active_exploitation'. Sub-capabilities are satisfied by
    the blanket grant (see consent.has_consent() for hierarchy rules).
    """
    log = Workspace(workspace).load_consent()
    try:
        consent_require(log, target, capability)  # type: ignore[arg-type]
    except PermissionError as exc:
        raise click.UsageError(str(exc)) from exc


def _target_host(url: str) -> str:
    """Extract and validate a hostname from an HTTP(S) URL."""
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise click.UsageError("Provide an absolute HTTP(S) URL, e.g. https://app.example.com/")
    return parsed.hostname.lower()


def _require_authorized_target(workspace: Path, url: str, capability: str = "active_exploitation") -> None:
    """Require an in-scope HTTP(S) target, valid consent, and request auditing."""
    target = _target_host(url)
    ws = Workspace(workspace)
    if classify(ws.load_scope(), url) != "allow":
        raise click.UsageError(
            f"Target '{url}' is not in the allowed scope. Load an allow rule before scanning."
        )
    _require_active_consent(workspace, target, capability)
    ws.enable_audit_logging()


def _require_authorized_host(workspace: Path, host: str, capability: str = "active_exploitation") -> None:
    """Require an in-scope host/domain and valid consent before a network action."""
    host = host.strip().lower().rstrip(".")
    if not host or "/" in host or ":" in host:
        raise click.UsageError("Provide a valid host or domain name.")
    ws = Workspace(workspace)
    if classify(ws.load_scope(), host) != "allow":
        raise click.UsageError(
            f"Target '{host}' is not in the allowed scope. Load an allow rule before scanning."
        )
    _require_active_consent(workspace, host, capability)
    ws.enable_audit_logging()


def _enable_audit(workspace: Path) -> None:
    """Wire workspace audit log into the scanner's global callback."""
    Workspace(workspace).enable_audit_logging()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
@main.group()
def scan() -> None:
    """Active vulnerability scanning — consent required for every target."""


@scan.command("crawl")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Starting URL for the crawler")
@click.option("--depth", default=2, show_default=True, help="Maximum crawl depth")
@click.option("--max-pages", default=100, show_default=True, help="Maximum pages to crawl")
@click.option("--import-graph", is_flag=True, default=False, help="Add discovered endpoints to graph")
def scan_crawl(workspace: Path, url: str, depth: int, max_pages: int, import_graph: bool) -> None:
    """BFS web crawler — discovers URLs respecting scope."""
    _require_authorized_target(workspace, url, "active_exploitation:crawl")
    from dribik.scanner import crawl
    ws = Workspace(workspace)
    scope_obj = ws.load_scope()
    click.echo(f"Crawling {url} (depth={depth}, max={max_pages}) …")
    results = crawl(url, scope_obj, max_depth=depth, max_pages=max_pages)
    click.echo(f"✓ Crawled {len(results)} page(s):")
    for r in results:
        status_str = str(r.status) if r.status else "ERR"
        click.echo(f"  [{status_str}] {r.url}")
    if import_graph and results:
        g = ws.load_graph()
        for r in results:
            if r.status and r.status < 400:
                add_endpoint(g, "GET", r.url, "dribik-crawl")
        ws.save_graph(g)
        click.echo(f"✓ Imported {len(results)} endpoint(s) into graph.")


@scan.command("tech")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL to fingerprint")
def scan_tech(workspace: Path, url: str) -> None:
    """Fingerprint server technology stack from HTTP headers and response body."""
    _require_authorized_target(workspace, url)
    from dribik.scanner import detect_tech_stack, http_get
    click.echo(f"Fingerprinting {url} …")
    result = http_get(url)
    if result.error:
        click.echo(f"Error: {result.error}", err=True)
        return
    ts = detect_tech_stack(result)
    click.echo(f"  Server:    {ts.server or 'unknown'}")
    click.echo(f"  Framework: {ts.framework or 'unknown'}")
    click.echo(f"  WAF:       {ts.waf or 'none detected'}")
    click.echo(f"  CMS:       {ts.cms or 'none detected'}")
    click.echo(f"  Language:  {ts.language or 'unknown'}")


@scan.command("headers")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
def scan_headers(workspace: Path, url: str, save: bool) -> None:
    """Check HTTP security headers (HSTS, CSP, X-Frame-Options, CORS, etc.)."""
    _require_authorized_target(workspace, url, "active_exploitation:headers")
    from dribik.vulns.headers import check_security_headers
    click.echo(f"Checking security headers: {url} …")
    checks, new_findings = check_security_headers(url)
    for check in checks:
        icon = "✓" if check.present else "✗"
        color = "green" if check.present else ("red" if check.severity in ("high", "critical") else "yellow")
        click.echo(click.style(f"  {icon} {check.header}", fg=color))
        if check.note:
            click.echo(f"      → {check.note}")
    if new_findings and save:
        ws = Workspace(workspace)
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


@scan.command("xss")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL")
@click.option("--params", default="", help="Comma-separated parameter names (optional)")
@click.option("--no-post", is_flag=True, default=False, help="Skip POST body injection")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
@click.option("--audit", is_flag=True, default=False, help="Log all requests to audit.jsonl")
def scan_xss(workspace: Path, url: str, params: str, no_post: bool, save: bool, audit: bool) -> None:
    """Probe URL parameters (GET + POST) for reflected XSS."""
    _require_authorized_target(workspace, url, "active_exploitation:xss")
    if audit:
        _enable_audit(workspace)
    from dribik.vulns.xss import scan_xss as _scan
    param_list = [p.strip() for p in params.split(",") if p.strip()] or None
    click.echo(f"Scanning XSS: {url} …")
    ws = Workspace(workspace)
    new_findings = _scan(url, params=param_list, asset_id=url, scope=ws.load_scope(), test_post=not no_post)
    if not new_findings:
        click.echo("  No XSS found.")
        return
    for f in new_findings:
        click.echo(click.style(f"  [FOUND] {f.title}", fg="red", bold=True))
    if save:
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


@scan.command("sqli")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL")
@click.option("--params", default="", help="Comma-separated parameter names (optional)")
@click.option("--no-post", is_flag=True, default=False, help="Skip POST body injection")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
@click.option("--audit", is_flag=True, default=False, help="Log all requests to audit.jsonl")
def scan_sqli(workspace: Path, url: str, params: str, no_post: bool, save: bool, audit: bool) -> None:
    """Probe URL parameters (GET + POST) for SQL Injection (error-based + time-based)."""
    _require_authorized_target(workspace, url, "active_exploitation:sqli")
    if audit:
        _enable_audit(workspace)
    from dribik.vulns.sqli import scan_sqli as _scan
    param_list = [p.strip() for p in params.split(",") if p.strip()] or None
    click.echo(f"Scanning SQLi: {url} …")
    ws = Workspace(workspace)
    new_findings = _scan(url, params=param_list, asset_id=url, scope=ws.load_scope(), test_post=not no_post)
    if not new_findings:
        click.echo("  No SQLi found.")
        return
    for f in new_findings:
        click.echo(click.style(f"  [FOUND] {f.title}", fg="red", bold=True))
    if save:
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


@scan.command("ssrf")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL")
@click.option("--params", default="", help="Comma-separated parameter names (optional)")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
def scan_ssrf(workspace: Path, url: str, params: str, save: bool) -> None:
    """Probe URL parameters for SSRF (cloud metadata + internal service probes)."""
    _require_authorized_target(workspace, url, "active_exploitation:ssrf")
    from dribik.vulns.ssrf import scan_ssrf as _scan
    param_list = [p.strip() for p in params.split(",") if p.strip()] or None
    click.echo(f"Scanning SSRF: {url} …")
    new_findings = _scan(url, params=param_list, asset_id=url)
    if not new_findings:
        click.echo("  No SSRF found.")
        return
    for f in new_findings:
        click.echo(click.style(f"  [FOUND] {f.title}", fg="red", bold=True))
    if save:
        ws = Workspace(workspace)
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


@scan.command("lfi")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL")
@click.option("--params", default="", help="Comma-separated parameter names (optional)")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
def scan_lfi(workspace: Path, url: str, params: str, save: bool) -> None:
    """Probe URL parameters for Local File Inclusion / Path Traversal."""
    _require_authorized_target(workspace, url, "active_exploitation:lfi")
    from dribik.vulns.lfi import scan_lfi as _scan
    param_list = [p.strip() for p in params.split(",") if p.strip()] or None
    click.echo(f"Scanning LFI: {url} …")
    new_findings = _scan(url, params=param_list, asset_id=url)
    if not new_findings:
        click.echo("  No LFI found.")
        return
    for f in new_findings:
        click.echo(click.style(f"  [FOUND] {f.title}", fg="red", bold=True))
    if save:
        ws = Workspace(workspace)
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


@scan.command("jwt")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--token", required=True, help="JWT token to audit")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
def scan_jwt(workspace: Path, token: str, save: bool) -> None:
    """Audit a JWT token (alg:none, weak secret, kid injection)."""
    from dribik.vulns.jwt_audit import audit_jwt
    click.echo("Auditing JWT …")
    new_findings = audit_jwt(token)
    if not new_findings:
        click.echo("  No JWT issues found.")
        return
    for f in new_findings:
        color = "red" if f.severity in ("critical", "high") else "yellow"
        click.echo(click.style(f"  [{f.severity.upper()}] {f.title}", fg=color, bold=True))
    if save:
        ws = Workspace(workspace)
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


@scan.command("redirect")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--url", required=True, help="Target URL")
@click.option("--params", default="", help="Comma-separated parameter names (optional)")
@click.option("--save", is_flag=True, default=False, help="Save findings to workspace")
def scan_redirect(workspace: Path, url: str, params: str, save: bool) -> None:
    """Probe URL parameters for open redirect vulnerabilities."""
    _require_authorized_target(workspace, url, "active_exploitation:redirect")
    from dribik.vulns.open_redirect import scan_open_redirect
    param_list = [p.strip() for p in params.split(",") if p.strip()] or None
    click.echo(f"Scanning open redirects: {url} …")
    new_findings = scan_open_redirect(url, params=param_list, asset_id=url)
    if not new_findings:
        click.echo("  No open redirects found.")
        return
    for f in new_findings:
        click.echo(click.style(f"  [FOUND] {f.title}", fg="yellow", bold=True))
    if save:
        ws = Workspace(workspace)
        bundle = ws.load_findings()
        existing_ids = {f.id for f in bundle.findings}
        added = [f for f in new_findings if f.id not in existing_ids]
        bundle.findings.extend(added)
        ws.save_findings(bundle)
        click.echo(f"✓ Saved {len(added)} finding(s).")


# ---------------------------------------------------------------------------
# subdomains
# ---------------------------------------------------------------------------
@main.group()
def subdomains() -> None:
    """Subdomain enumeration and takeover detection."""


@subdomains.command("enum")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--domain", required=True, help="Base domain to enumerate")
@click.option("--wordlist", type=click.Path(path_type=Path), default=None, help="Custom wordlist file")
@click.option("--workers", default=50, show_default=True)
@click.option("--import-graph", is_flag=True, default=False, help="Add discovered hosts to graph")
def subdomains_enum(workspace: Path, domain: str, wordlist: Path | None, workers: int, import_graph: bool) -> None:
    """DNS brute-force subdomain enumeration."""
    _require_authorized_host(workspace, domain)
    from dribik.subdomains import enumerate_subdomains
    wl = None
    if wordlist:
        wl = [ln.strip() for ln in wordlist.read_text(encoding="utf-8").splitlines() if ln.strip()]
    click.echo(f"Enumerating subdomains of {domain} …")
    results = enumerate_subdomains(domain, wordlist=wl, max_workers=workers)
    if not results:
        click.echo("  No subdomains resolved.")
        return
    click.echo(f"  Found {len(results)} subdomain(s):")
    for r in results:
        click.echo(f"    {r['fqdn']}  →  {', '.join(r['ips'])}")
    if import_graph:
        ws = Workspace(workspace)
        g = ws.load_graph()
        for r in results:
            add_host(g, r["fqdn"], "dribik-dns", domain=domain, ips=r["ips"], alive=r["alive"])
        ws.save_graph(g)
        click.echo(f"✓ Imported {len(results)} host(s) into graph.")


@subdomains.command("takeover")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--fqdn", required=True, help="Fully-qualified domain name to check")
@click.option("--save", is_flag=True, default=False, help="Save finding if vulnerable")
def subdomains_takeover(workspace: Path, fqdn: str, save: bool) -> None:
    """Check a subdomain for potential takeover vulnerability."""
    _require_authorized_host(workspace, fqdn)
    from dribik.models import CVSSVector, Finding
    from dribik.subdomains import check_subdomain_takeover
    click.echo(f"Checking takeover risk for {fqdn} …")
    result = check_subdomain_takeover(fqdn)
    if result["vulnerable"]:
        click.echo(click.style(
            f"  [VULNERABLE] {fqdn} — {result['service'] or 'dangling DNS'}",
            fg="red", bold=True
        ))
        click.echo(f"  Note: {result['note']}")
        if save:
            ws = Workspace(workspace)
            bundle = ws.load_findings()
            f = Finding(
                id=f"TAKEOVER-{fqdn.replace('.', '-').upper()[:20]}",
                title=f"Subdomain Takeover: {fqdn}",
                severity="high",
                vuln_type="SubdomainTakeover",
                asset_id=f"host:{fqdn}",
                summary=result["note"],
                remediation="Remove the dangling DNS record or re-claim the external resource.",
                cwe_id="CWE-1021",
                cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
            )
            bundle.findings.append(f)
            ws.save_findings(bundle)
            click.echo("✓ Finding saved.")
    else:
        click.echo(click.style(f"  {fqdn} — no takeover indicators found.", fg="green"))


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
@main.group()
def report() -> None:
    """Generate pentest reports."""


@report.command("write")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--out", required=True, type=click.Path(path_type=Path))
def report_write(workspace: Path, out: Path) -> None:
    """Generate a Markdown assessment report."""
    ws = Workspace(workspace)
    text = write_report(
        meta=ws.load_meta(),
        graph=ws.load_graph(),
        scope=ws.load_scope(),
        findings=ws.load_findings().findings,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    click.echo(f"✓ Markdown report written to {out}")


@report.command("html")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--out", required=True, type=click.Path(path_type=Path))
def report_html(workspace: Path, out: Path) -> None:
    """Generate a self-contained HTML pentest report."""
    ws = Workspace(workspace)
    html = write_html_report(
        meta=ws.load_meta(),
        graph=ws.load_graph(),
        scope=ws.load_scope(),
        findings=ws.load_findings().findings,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    click.echo(f"✓ HTML report written to {out}")


@report.command("json")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--out", required=True, type=click.Path(path_type=Path))
def report_json(workspace: Path, out: Path) -> None:
    """Generate a machine-readable JSON report."""
    ws = Workspace(workspace)
    text = write_json_report(
        meta=ws.load_meta(),
        graph=ws.load_graph(),
        scope=ws.load_scope(),
        findings=ws.load_findings().findings,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    click.echo(f"✓ JSON report written to {out}")


# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------
@main.group()
def collection() -> None:
    """Postman-compatible collection export."""


@collection.command("write")
@click.argument("workspace", type=click.Path(path_type=Path))
@click.option("--out", required=True, type=click.Path(path_type=Path))
def collection_write(workspace: Path, out: Path) -> None:
    """Export in-scope endpoints as a Postman collection."""
    ws = Workspace(workspace)
    meta = ws.load_meta()
    payload = to_postman(ws.load_graph(), ws.load_scope(), f"{meta.program} (in-scope)")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    click.echo(f"✓ Wrote {out} ({len(payload['item'])} request(s))")
