"""Shared helpers for vulnerability probes.

Payload files are user-editable package data.  Keep loading deterministic,
deduplicated, and tolerant of a missing optional file so scanners remain
usable from source checkouts and frozen installs.
"""

from __future__ import annotations

from pathlib import Path


def load_payloads(filename: str, fallback: list[str]) -> list[str]:
    """Load non-empty, non-comment payload lines, preserving order."""
    path = Path(__file__).parent.parent / "payloads" / filename
    if not path.is_file():
        return list(dict.fromkeys(fallback))
    values = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return list(dict.fromkeys(values)) or list(dict.fromkeys(fallback))
