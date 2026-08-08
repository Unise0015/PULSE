import pytest
from unittest.mock import patch, MagicMock
from pulse.version_intelligence.recommendation_engine import analyze_upgrade_recommendation
from pulse.version_intelligence.models import RecommendationMethod
from pulse.domain.models import VulnerabilityFinding, PackageInfo, VersionMetadata

def test_django_3_2_vulnerable_candidate_rejection_and_promotion():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="PyPI")
    finding = VulnerabilityFinding(cve_id="CVE-2023-0001", package=pkg, fix_version="5.1.14", cvss_severity="HIGH")
    vm = MagicMock(latest_stable_version="5.1.15", latest_version="5.1.15")

    # 5.1.14 is vulnerable (blocking_findings > 0), 5.1.15 is safe (blocking_findings == 0)
    def mock_verify(pkg_name, version, ecosystem):
        if version == "5.1.14":
            return MagicMock(blocking_findings=2, total_findings=2, cache_hit=False)
        return MagicMock(blocking_findings=0, total_findings=0, cache_hit=False)

    with patch("pulse.version_intelligence.recommendation_engine.UpgradeVerificationService") as mock_service_cls:
        mock_service_cls.return_value.verify_candidate.side_effect = mock_verify

        rec = analyze_upgrade_recommendation(
            pkg_name="Django",
            ecosystem="PyPI",
            current_version="3.2",
            findings=[finding],
            version_metadata=vm,
            verify_candidate=True
        )

        assert rec.recommended_version == "5.1.15"
        assert "5.1.14" in rec.rejected_candidates
        assert rec.verified_safe
        assert rec.evidence.method == RecommendationMethod.VERIFIED_SCAN

def test_evidence_hierarchy_prevents_downgrade():
    from pulse.version_intelligence.models import RecommendationEvidence
    ev = RecommendationEvidence(method=RecommendationMethod.VERIFIED_SCAN)
    lower_ev = RecommendationEvidence(method=RecommendationMethod.ADVISORY_CONFIRMED)

    ev.upgrade_to(lower_ev)
    assert ev.method == RecommendationMethod.VERIFIED_SCAN
