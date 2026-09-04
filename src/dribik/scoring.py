"""Scoring — confidence and CVSS-based risk scoring."""

from __future__ import annotations

from dribik.models import Finding

# CVSS → confidence weight mapping
_CVSS_WEIGHT = {
    (0.0, 4.0): 0.1,
    (4.0, 7.0): 0.3,
    (7.0, 9.0): 0.5,
    (9.0, 10.1): 0.7,
}


def _cvss_weight(score: float) -> float:
    for (lo, hi), w in _CVSS_WEIGHT.items():
        if lo <= score < hi:
            return w
    return 0.1


def score_finding(finding: Finding) -> float:
    """
    Confidence score (0–1) blending:
      - Template freshness (35%)
      - Response-diff agreement (25%)
      - Operator-validated flag (20%)
      - CVSS severity weight (20%)
    """
    freshness = max(0.0, 1.0 - (finding.template_age_days / 365.0))
    diff = min(1.0, max(0.0, finding.response_diff_agreement))
    validated = 1.0 if finding.operator_validated else 0.0
    cvss_w = _cvss_weight(finding.cvss_score)

    value = (
        0.35 * freshness
        + 0.25 * diff
        + 0.20 * validated
        + 0.20 * cvss_w
    )
    return round(min(1.0, max(0.0, value)), 4)


def apply_scores(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        finding.confidence = score_finding(finding)
    return findings


def risk_matrix(findings: list[Finding]) -> dict:
    """Return severity × confidence count matrix."""
    matrix: dict[str, dict[str, int]] = {}
    for f in findings:
        sev = f.severity
        bucket = (
            "high_conf" if (f.confidence or 0) >= 0.7
            else "med_conf" if (f.confidence or 0) >= 0.4
            else "low_conf"
        )
        matrix.setdefault(sev, {}).setdefault(bucket, 0)
        matrix[sev][bucket] += 1
    return matrix
