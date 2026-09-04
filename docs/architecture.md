# Architecture — Dribik 0.1.0-beta

This document describes the data model and safety boundaries of Dribik. It is not an attack playbook.

## 1. Unified data layer

All assets live in one graph (`workspace/graph.json`).

**Node types**

| Type | Identity | Typical fields |
| --- | --- | --- |
| `domain` | registrable or program root | `name` |
| `host` | FQDN | `fqdn`, `alive`, `ips`, `wildcard_risk` |
| `endpoint` | method + URL | `method`, `url`, `status` |
| `param` | endpoint + name + location | `name`, `in` (`query` / `body` / `header` / `path`) |
| `js_route` | URL or path found in JavaScript | `path`, `source_url` |

**Edges** are parent/child (`domain → host → endpoint → param`) plus `extracted_from` for JS routes.

**Provenance:** every node stores `sources: [{tool, imported_at}]`. Imports from overlapping enumerators are merged by identity; sources accumulate instead of duplicating nodes.

**Identity keys**

- host: lowercase FQDN  
- endpoint: `METHOD` + normalized URL (scheme, host, path; sorted query keys, no fragments)  
- param: parent endpoint id + location + name  
- js_route: source URL + path

## 2. Recon and discovery

Dribik combines passive discovery with authorized active discovery.

1. **Passive-first:** certificate-transparency lookup and graph planning avoid direct target contact.
2. **Authorized discovery:** robots/sitemaps, crawler, content discovery, and subdomain enumeration require matching scope and consent before they send traffic.
3. **Wildcard risk:** if the operator marks a domain `wildcard_risk: true` (or imports that flag), HTTP liveness from catch-all DNS should not be treated as a distinct live host. Detection of wildcards is left to the operator’s DNS tooling; Dribik stores the flag so reports and collections can de-weight those hosts.

Dribik deliberately avoids high-rate fuzzing, exploit chaining, credential harvesting, and C2
integration. `recon tokens` emits unique path segments and parameter names already observed; it is
inventory, not a fuzzing engine.

## 3. Scan engine and confidence scoring

The scan commands cover common, bounded checks (security headers, reflected XSS, SQLi, SSRF, LFI,
open redirect, JWT audit, and technology fingerprinting). They all pass through the same scope,
consent, rate-limit, and audit mechanisms. Findings can also be imported after manual validation.
Each finding may include:

- `template_age_days` — older templates score lower (staleness / unmaintained signatures)  
- `response_diff_agreement` — 0.0–1.0, how strongly a baseline vs. candidate response difference supports the claim (operator-supplied; Skillet does not probe)  
- `operator_validated` — boolean  

Score in `[0, 1]`:

```
0.35 * freshness + 0.45 * response_diff_agreement + 0.20 * validated
```

where `freshness = max(0, 1 - template_age_days / 365)`.

## 4. Human-in-the-loop

Dribik stores `notes` on endpoints (repeater-style **documentation**: method, URL, headers the
operator already used). Raw HTTP requests copied from an intercepting proxy can be replayed only
after scope and consent checks; transport-sensitive headers are stripped or rebuilt safely.

Consent file (`consent.json`) lists `{target, capability, operator, granted_at, expires_at}`. Report and collection writers require scope match; they do not require consent because they do not touch the target. Any future network client must call `consent.require(...)`.

## 5. Reporting

**Markdown report:** program name, graph summary, findings sorted by confidence, explicit **Out of scope** section so ROE violations are visible.

**Postman Collection v2.1:** one request per in-scope `endpoint` node. Out-of-scope endpoints are omitted (and counted in the report).

## Workspace files

```
workspace/
  dribik.yaml       # program metadata + schema version
  graph.json
  scope.yaml
  consent.json
  findings.json
  notes.json        # optional operator notes keyed by node id
```

Schema version for 0.1.0-beta is `1`.
