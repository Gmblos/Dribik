"""Workspace — on-disk persistence layer with audit logging."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from dribik.models import (
    AuditEntry,
    ConsentLog,
    FindingsFile,
    Graph,
    Scope,
    WorkspaceMeta,
)

logger = logging.getLogger(__name__)

GRAPH    = "graph.json"
SCOPE    = "scope.yaml"
CONSENT  = "consent.json"
FINDINGS = "findings.json"
META     = "dribik.yaml"
NOTES    = "notes.json"
AUDIT    = "audit.jsonl"   # One JSON line per HTTP request sent to any target


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def create(self, program: str) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if not (self.root / GRAPH).exists():
            (self.root / GRAPH).write_text(Graph().model_dump_json(indent=2), encoding="utf-8")
        if not (self.root / SCOPE).exists():
            scope = Scope(program=program)
            (self.root / SCOPE).write_text(
                yaml.safe_dump(scope.model_dump(), sort_keys=False), encoding="utf-8"
            )
        if not (self.root / CONSENT).exists():
            (self.root / CONSENT).write_text(
                ConsentLog().model_dump_json(indent=2), encoding="utf-8"
            )
        if not (self.root / FINDINGS).exists():
            (self.root / FINDINGS).write_text(
                FindingsFile().model_dump_json(indent=2), encoding="utf-8"
            )
        if not (self.root / NOTES).exists():
            (self.root / NOTES).write_text("{}", encoding="utf-8")
        # audit.jsonl is created lazily when the first entry is written
        meta = WorkspaceMeta(program=program)
        (self.root / META).write_text(
            yaml.safe_dump(meta.model_dump(), sort_keys=False), encoding="utf-8"
        )

    def health_check(self) -> dict[str, str]:
        """Validate every required workspace record without changing it."""
        checks: dict[str, str] = {}
        loaders = {
            META: self.load_meta,
            GRAPH: self.load_graph,
            SCOPE: self.load_scope,
            CONSENT: self.load_consent,
            FINDINGS: self.load_findings,
        }
        for filename, load in loaders.items():
            try:
                load()
                checks[filename] = "ok"
            except Exception as exc:
                checks[filename] = f"error: {exc}"
        checks[NOTES] = "ok" if (self.root / NOTES).exists() else "missing"
        checks[AUDIT] = "ok" if (self.root / AUDIT).exists() else "not created yet"
        return checks

    # ------------------------------------------------------------------
    # Meta / graph / scope / consent / findings
    # ------------------------------------------------------------------
    def load_meta(self) -> WorkspaceMeta:
        data = yaml.safe_load((self.root / META).read_text(encoding="utf-8"))
        return WorkspaceMeta.model_validate(data)

    def load_graph(self) -> Graph:
        return Graph.model_validate_json((self.root / GRAPH).read_text(encoding="utf-8"))

    def save_graph(self, graph: Graph) -> None:
        (self.root / GRAPH).write_text(graph.model_dump_json(indent=2), encoding="utf-8")

    def load_scope(self) -> Scope:
        data = yaml.safe_load((self.root / SCOPE).read_text(encoding="utf-8"))
        return Scope.model_validate(data)

    def save_scope(self, scope: Scope) -> None:
        (self.root / SCOPE).write_text(
            yaml.safe_dump(scope.model_dump(), sort_keys=False), encoding="utf-8"
        )

    def load_consent(self) -> ConsentLog:
        return ConsentLog.model_validate_json((self.root / CONSENT).read_text(encoding="utf-8"))

    def save_consent(self, log: ConsentLog) -> None:
        (self.root / CONSENT).write_text(log.model_dump_json(indent=2), encoding="utf-8")

    def load_findings(self) -> FindingsFile:
        return FindingsFile.model_validate_json((self.root / FINDINGS).read_text(encoding="utf-8"))

    def save_findings(self, findings: FindingsFile) -> None:
        (self.root / FINDINGS).write_text(findings.model_dump_json(indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Audit log — append-only JSONL
    # ------------------------------------------------------------------
    def append_audit(self, entry: AuditEntry) -> None:
        """Append one audit entry to audit.jsonl (created on first write)."""
        audit_path = self.root / AUDIT
        with audit_path.open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")

    def load_audit(self) -> list[AuditEntry]:
        """Return all audit entries (empty list if file doesn't exist)."""
        audit_path = self.root / AUDIT
        if not audit_path.exists():
            return []
        entries: list[AuditEntry] = []
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(AuditEntry.model_validate_json(line))
                except Exception as exc:
                    logger.debug("Failed to parse audit line: %s", exc)
        return entries

    def enable_audit_logging(self) -> None:
        """Wire workspace.append_audit into scanner's global audit callback."""
        from dribik.scanner import set_audit_callback
        set_audit_callback(self.append_audit)
