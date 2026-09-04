# Changelog

## 0.1.0-beta — 2026-09-04

### Changed

- Active HTTP requests no longer follow redirects by default, preventing scope drift.
- Robots, sitemap, and takeover checks now use the audited HTTP client.
- Scope controls now apply in reusable scanner APIs as well as the CLI.
- Added `dribik doctor` for non-mutating workspace health validation.

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
