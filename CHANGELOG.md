# Changelog

## 0.1.0-beta — 2026-09-04

### Added

- Raw HTTP request replay from proxy exports, protected by the normal scope, consent,
  rate-limit, and audit controls.
- Authorized common-path content discovery with soft-404 filtering.
- SARIF report export for code-scanning integrations.
- A 70% coverage gate in CI, dependency-update automation, and polished GitHub project docs.

### Fixed & Quality Hardening

- Removed dead duplicate `_inject_get` definition in `src/dribik/vulns/sqli.py`.
- Replaced bare `except Exception: pass` in `recon.py` (crt.sh lookup) with explicit network/decoding error handling and debug logging.
- Addressed silent exception swallowing across `scanner.py`, `workspace.py`, and `jwt_audit.py`.
- Resolved all 32 strict type errors across `src/`, achieving 100% clean check under `mypy src --strict`.
- Expanded Ruff ruleset to enforce `E`, `W`, `F`, `I`, `B` (flake8-bugbear), and `S110`/`S112` (try-except pass/continue).
- Integrated `mypy src` and `pytest --cov=dribik` coverage reporting directly into GitHub Actions CI.

## 0.0.2-beta — 2026-09-04

### Added

- Workspace layout (`graph.json`, `scope.yaml`, `consent.json`, `findings.json`)
- Unified asset graph with merge/dedupe and source provenance
- Scope / ROE matching (domains, host suffixes, URL prefixes, explicit denials)
- Per-target consent records (capability + timestamp + operator)
- Passive-first recon plan and certificate-transparency discovery
- Token extraction from known endpoints and JS routes
- Finding confidence scoring (template age + response-diff agreement)
- Markdown, HTML, and JSON reports plus Postman Collection v2.1 export
- CLI, tests, GitHub Actions CI, contribution and security policy
- Fine-grained scope and consent gates for every active HTTP scan
- Append-only request audit trail for every active HTTP scan
- Redirect-preserving HTTP mode for reliable open-redirect checks

### Not included (by design)

- Credential harvesting, exploit chaining, C2 integration, or testing outside written authorization
