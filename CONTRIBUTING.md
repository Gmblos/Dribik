# Contributing to Skillet

Thank you for helping with the authorized-assessment workspace.

## Scope of contributions (0.0.1-beta)

**Welcome**

- Graph merge/dedupe bugs, scope matching, scoring, report/collection export
- Tests, docs, CI, accessibility of the CLI
- Importers for **already collected** JSON/CSV inventories (no live scanners)

**Not accepted**

- Exploit payloads, proof-of-concept attacks, or “how to reproduce” exploit steps
- Fuzzing / brute-force / injection / template-scan engines
- Wordlists intended for attacking live services
- Circumvention of consent or scope gates

## Dev setup

```bash
python -m venv .venv
pip install -e ".[dev]"
pytest
ruff check src tests
```

## Pull requests

- Keep diffs focused.
- Add or update tests for graph, scope, and scoring changes.
- Do not commit real engagement data, cookies, or secrets.
