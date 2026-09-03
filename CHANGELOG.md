# Changelog

## 0.0.1-beta — 2026-09-02

### Added

- Workspace layout (`graph.json`, `scope.yaml`, `consent.json`, `findings.json`)
- Unified asset graph with merge/dedupe and source provenance
- Scope / ROE matching (domains, host suffixes, URL prefixes, explicit denials)
- Per-target consent records (capability + timestamp + operator)
- Passive-first recon **plan** (no active enumerator)
- Token extraction from known endpoints and JS routes
- Finding confidence scoring (template age + response-diff agreement)
- Markdown report and Postman Collection v2.1 export
- CLI, tests, GitHub Actions CI, contribution and security policy

### Not included (by design)

- Subdomain brute-force, HTTP fuzzing, vulnerability templates, injection or exploitation engines
