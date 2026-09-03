"""Consent management — grant, check, require (with sub-capability hierarchy)."""

from __future__ import annotations

from datetime import UTC, datetime

from dribik.models import Capability, ConsentLog, ConsentRecord, utc_now


def grant(
    log: ConsentLog,
    *,
    target: str,
    capability: Capability,
    operator: str,
    expires_at: str | None = None,
    note: str = "",
) -> ConsentRecord:
    record = ConsentRecord(
        target=target,
        capability=capability,
        operator=operator,
        granted_at=utc_now(),
        expires_at=expires_at,
        note=note,
    )
    log.records.append(record)
    return record


def _not_expired(record: ConsentRecord) -> bool:
    if not record.expires_at:
        return True
    expiry = datetime.fromisoformat(record.expires_at.replace("Z", "+00:00"))
    now = datetime.now(UTC)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return now <= expiry


def has_consent(log: ConsentLog, target: str, capability: Capability) -> bool:
    """
    Return True if *target* has a valid (non-expired) consent record for
    *capability*.

    Sub-capability hierarchy:
      - A specific sub-capability ('active_exploitation:sqli') is satisfied by:
          1. An exact match for 'active_exploitation:sqli', OR
          2. The blanket 'active_exploitation' capability.
      - The blanket 'active_exploitation' is NOT satisfied by a sub-capability.
    """
    checks: list[str] = [capability]
    # If this is a sub-capability (e.g. "active_exploitation:sqli"),
    # also accept the parent blanket capability ("active_exploitation").
    if ":" in capability:
        parent = capability.rsplit(":", 1)[0]
        checks.append(parent)

    t = target.strip().lower()
    for record in log.records:
        if record.capability not in checks:
            continue
        if record.target.strip().lower() != t:
            continue
        if _not_expired(record):
            return True
    return False


def require(log: ConsentLog, target: str, capability: Capability) -> None:
    """
    Raise PermissionError if no valid consent exists.
    Respects the sub-capability hierarchy — see has_consent() for rules.
    """
    if not has_consent(log, target, capability):
        parent = capability.rsplit(":", 1)[0] if ":" in capability else capability
        raise PermissionError(
            f"No valid consent for capability '{capability}' on target '{target}'. "
            f"Grant with: dribik consent grant <ws> --target {target} "
            f"--capability {capability} --operator <name>\n"
            f"Or grant the blanket capability: --capability {parent}"
        )
