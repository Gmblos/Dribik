# Dribik — Authorized Web Pentesting Workspace

> **⚠️ For authorized use only.** Use Dribik exclusively on systems you own or have **explicit written permission** to assess.

Dribik is a Python CLI toolkit for structured, consent-tracked web penetration testing. It gives you an asset graph, scope enforcement, active vulnerability scanners, and professional report generation — all wired together in one workspace.

---

## Features

| Module | What it does |
|---|---|
| **Asset graph** | Merges hosts, endpoints, params, JS routes from multiple tools into a deduplicated graph |
| **Scope / ROE** | Allow/deny rules (domain suffix, host exact, URL prefix) — checked before every active probe |
| **Consent log** | Per-target, per-capability consent records. All scan commands refuse to run without a valid entry |
| **Active scanners** | XSS, SQLi (error + time-based), SSRF, LFI, open redirect, security headers, JWT audit |
| **Crawler** | BFS crawler respecting scope rules |
| **Subdomain enum** | DNS brute-force + subdomain takeover detection |
| **Passive recon** | crt.sh certificate transparency, robots.txt, sitemap.xml |
| **CVSS scoring** | CVSS v3.1 base score on every finding, risk matrix output |
| **Reports** | Markdown, HTML (self-contained), JSON (CI-ready) |
| **Postman export** | In-scope endpoints exported as a Postman v2.1 collection |

---

## Installation

```bash
pip install -e ".[dev]"
```

For the optional richer HTTP client and extras:

```bash
pip install -e ".[full]"
```

---

## Quick start

```bash
# 1. Create a workspace
dribik init ./my-engagement --program "Acme Corp"

# 2. Load your scope (allow/deny rules)
dribik scope load ./my-engagement --file examples/scope.yaml

# 3. Record written consent before any active scanning
dribik consent grant ./my-engagement \
  --target api.acme.com \
  --capability active_exploitation \
  --operator "alice" \
  --note "SOW ref #1234"

# 4. Passive recon (no target contact)
dribik recon passive-dns ./my-engagement --domain acme.com --import-graph
dribik recon robots ./my-engagement --url https://acme.com --import-graph

# 5. Active scanning (blocked without consent)
dribik scan headers ./my-engagement --url https://api.acme.com/ --save
dribik scan xss     ./my-engagement --url "https://api.acme.com/search?q=x" --save
dribik scan sqli    ./my-engagement --url "https://api.acme.com/items?id=1" --save
dribik scan ssrf    ./my-engagement --url "https://api.acme.com/fetch?url=x" --save
dribik scan lfi     ./my-engagement --url "https://api.acme.com/file?path=x" --save
dribik scan jwt     ./my-engagement --token "eyJ..." --save
dribik scan crawl   ./my-engagement --url https://api.acme.com/ --import-graph

# 6. Subdomain enumeration
dribik subdomains enum      ./my-engagement --domain acme.com --import-graph
dribik subdomains takeover  ./my-engagement --fqdn staging.acme.com --save

# 7. Generate reports
dribik report write  ./my-engagement --out ./reports/report.md
dribik report html   ./my-engagement --out ./reports/report.html
dribik report json   ./my-engagement --out ./reports/report.json

# 8. Postman collection
dribik collection write ./my-engagement --out ./acme.postman_collection.json
```

---

## CLI Reference

### Core

| Command | Purpose |
|---|---|
| `dribik init <path> --program <name>` | Create workspace |
| `dribik scope load <ws> --file <yaml>` | Load scope/ROE rules |
| `dribik scope check <ws> <asset>` | Classify asset (allow/deny/unknown) |
| `dribik consent grant <ws> --target <h> --capability <c> --operator <o>` | Record consent |
| `dribik graph import <ws> --file <json>` | Merge asset bundle |
| `dribik graph add <ws> --host/--url` | Add asset manually |
| `dribik graph status <ws>` | Node count summary |

### Recon (passive — no direct target contact)

| Command | Purpose |
|---|---|
| `dribik recon plan <ws>` | Passive recon plan from graph |
| `dribik recon tokens <ws>` | Extract path/param tokens |
| `dribik recon passive-dns <ws> --domain <d>` | crt.sh CT log lookup |
| `dribik recon robots <ws> --url <url>` | robots.txt + sitemap |

### Scan (active — consent required)

| Command | Purpose |
|---|---|
| `dribik scan crawl <ws> --url <url>` | BFS crawler |
| `dribik scan tech <ws> --url <url>` | Tech-stack fingerprint |
| `dribik scan headers <ws> --url <url>` | Security header audit |
| `dribik scan xss <ws> --url <url>` | Reflected XSS probes |
| `dribik scan sqli <ws> --url <url>` | SQL injection probes |
| `dribik scan ssrf <ws> --url <url>` | SSRF probes |
| `dribik scan lfi <ws> --url <url>` | LFI / path traversal |
| `dribik scan jwt <ws> --token <t>` | JWT audit |
| `dribik scan redirect <ws> --url <url>` | Open redirect probes |

### Subdomains

| Command | Purpose |
|---|---|
| `dribik subdomains enum <ws> --domain <d>` | DNS brute-force |
| `dribik subdomains takeover <ws> --fqdn <f>` | Takeover detection |

### Reports & Export

| Command | Purpose |
|---|---|
| `dribik report write <ws> --out <file>` | Markdown report |
| `dribik report html <ws> --out <file>` | HTML report |
| `dribik report json <ws> --out <file>` | JSON report (CI-ready) |
| `dribik collection write <ws> --out <file>` | Postman collection |
| `dribik findings import <ws> --file <json>` | Import findings |
| `dribik findings score <ws>` | Re-score findings |
| `dribik findings risk-matrix <ws>` | Severity × confidence matrix |

---

## Consent model

Every `scan` and `subdomains` command calls `consent.require()` before sending any payload to a target. If no matching `active_exploitation` consent record exists for the target host, the command exits immediately with a non-zero code.

```
Error: No valid consent for capability 'active_exploitation' on target 'example.com'.
Record consent with `dribik consent grant` after written authorization.
```

The consent log is stored in `consent.json` inside your workspace and is included in reports.

---

## Workspace layout

```
my-engagement/
├── dribik.yaml       # Program metadata and version
├── graph.json        # Asset graph (hosts, endpoints, params, JS routes)
├── scope.yaml        # Allow/deny scope rules
├── consent.json      # Consent log
├── findings.json     # Findings with CVSS, PoC, remediation
└── notes.json        # Free-form notes
```

---

## Running tests

```bash
pytest tests/ -v
```

The test suite covers: scope, consent, graph, scoring (CVSS), reports (Markdown/HTML/JSON), CLI (including consent gate enforcement), collection export, recon, and all vuln modules (XSS, SQLi, LFI, headers, JWT, open redirect) using mocks — no network required.

---

## Rules of use

- **Only test systems you own or are explicitly authorized to assess.**
- The consent log is not a substitute for a signed scope-of-work or rules-of-engagement document.
- Out-of-scope assets are retained in the graph for audit but excluded from collections and flagged in reports.
- Do not submit pull requests that add automated exploit chains, C2 integration, or credential harvesting.

---

## Versioning

**0.0.2-beta** (`0.0.2b0` on PyPI-style metadata).  
Workspace format (`schema_version: 1`) is stable within the 0.0.x series.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
