# Contributing to Dribik

Thank you for helping improve this authorized-assessment workspace.

## Scope of contributions (0.1.0-beta)

**Welcome**

- Graph merge/dedupe bugs, scope matching, consent enforcement, scoring, report/collection export
- Tests, docs, CI, accessibility of the CLI
- Importers for **already collected** JSON/CSV inventories
- Safety-preserving improvements to the existing authorized scan modules

**Not accepted**

- Exploit payloads, proof-of-concept attacks, or “how to reproduce” exploit steps
- Unbounded fuzzing, brute-force, exploit chains, or injection engines that bypass the workspace gates
- Wordlists intended for attacking live services
- Circumvention of consent or scope gates

## Dev setup

```bash
python -m venv .venv
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## Pull requests

- Keep diffs focused.
- Add or update tests for graph, scope, and scoring changes.
- Do not commit real engagement data, cookies, or secrets.
