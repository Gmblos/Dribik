"""Tests — confidence scoring (migrated to dribik + updated formula)."""
from dribik.models import CVSSVector, Finding
from dribik.scoring import score_finding, risk_matrix


def test_validated_fresh_high_cvss_scores_max():
    finding = Finding(
        id="1",
        title="t",
        asset_id="x",
        template_age_days=0,
        response_diff_agreement=1.0,
        operator_validated=True,
        cvss=CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    score = score_finding(finding)
    # 0.35*1 + 0.25*1 + 0.20*1 + 0.20*0.7 = 0.94
    assert score == 0.94


def test_stale_unvalidated_no_cvss_scores_zero():
    finding = Finding(
        id="2",
        title="t",
        asset_id="x",
        template_age_days=365,
        response_diff_agreement=0.0,
        operator_validated=False,
        # no cvss → cvss_score=0.0 → weight=0.1
    )
    score = score_finding(finding)
    # 0.35*0 + 0.25*0 + 0.20*0 + 0.20*0.1 = 0.02
    assert score == 0.02


def test_risk_matrix_buckets():
    findings = [
        Finding(id="a", title="a", asset_id="x", severity="critical", confidence=0.9),
        Finding(id="b", title="b", asset_id="x", severity="critical", confidence=0.5),
        Finding(id="c", title="c", asset_id="x", severity="high", confidence=0.3),
    ]
    matrix = risk_matrix(findings)
    assert matrix["critical"]["high_conf"] == 1
    assert matrix["critical"]["med_conf"] == 1
    assert matrix["high"]["low_conf"] == 1


def test_cvss_base_score_critical():
    v = CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert v.base_score == 9.8


def test_cvss_base_score_zero_no_impact():
    v = CVSSVector(vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert v.base_score == 0.0
