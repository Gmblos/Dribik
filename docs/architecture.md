# Architecture — Skillet 0.0.1-beta

This document describes **what exists in beta** and **what is specified but not shipped**. It is not an attack playbook.

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

## 2. Adaptive recon engine (policy only)

Beta ships a **planner**, not an enumerator.

1. **Passive-first:** treat imported hosts as coming from API/passive sources the operator already ran under authorization.  
2. **Escalate only as a review item:** hosts with no `ips` and `alive != true` are listed as `needs_operator_review`. Skillet does not brute-force labels.  
3. **Wildcard risk:** if the operator marks a domain `wildcard_risk: true` (or imports that flag), HTTP liveness from catch-all DNS should not be treated as a distinct live host. Detection of wildcards is left to the operator’s DNS tooling; Skillet stores the flag so reports and collections can de-weight those hosts.

Future versions may add *read-only* adapters (certificate transparency, program-provided asset APIs) behind the same consent and scope gates. They will not add wordlist brute-force.

## 3. Smart fuzzing layer (not shipped)

Specified for later discussion, **absent from 0.0.1-beta**:

- High-rate HTTP fuzzing  
- Auto-hitting generated paths  
- WAF/rate-limit backoff loops against live targets  

**Shipped instead:** `recon tokens` walks the graph and emits unique path segments and parameter names already observed. That is inventory, not a fuzzer.

## 4. Scan engine and confidence scoring

**Not shipped:** template runners, injection testers, exploitation depth, or payload libraries.

**Shipped:** findings are records the operator imports after validation. Each finding may include:

- `template_age_days` — older templates score lower (staleness / unmaintained signatures)  
- `response_diff_agreement` — 0.0–1.0, how strongly a baseline vs. candidate response difference supports the claim (operator-supplied; Skillet does not probe)  
- `operator_validated` — boolean  

Score in `[0, 1]`:

```
0.35 * freshness + 0.45 * response_diff_agreement + 0.20 * validated
```

where `freshness = max(0, 1 - template_age_days / 365)`.

Active exploitation, if ever considered, would be a separate plugin with **per-target consent** (`capability: active_exploitation`). That plugin is not in this repository.

## 5. Human-in-the-loop

Beta stores `notes` on endpoints (repeater-style **documentation**: method, URL, headers the operator already used). It does not send traffic and does not mutate payloads across a grid of positions.

Consent file (`consent.json`) lists `{target, capability, operator, granted_at, expires_at}`. Report and collection writers require scope match; they do not require consent because they do not touch the target. Any future network client must call `consent.require(...)`.

## 6. Reporting

**Markdown report:** program name, graph summary, findings sorted by confidence, explicit **Out of scope** section so ROE violations are visible.

**Postman Collection v2.1:** one request per in-scope `endpoint` node. Out-of-scope endpoints are omitted (and counted in the report).

## Workspace files

```
workspace/
  skillet.yaml      # program metadata + schema version
  graph.json
  scope.yaml
  consent.json
  findings.json
  notes.json        # optional operator notes keyed by node id
```

Schema version for 0.0.1-beta is `1`.
