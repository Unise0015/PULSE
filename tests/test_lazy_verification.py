import pytest
from unittest.mock import patch, MagicMock
from pulse.version_intelligence.recommendation_engine import analyze_upgrade_recommendation
from pulse.version_intelligence.models import RecommendationMethod
from pulse.domain.models import VulnerabilityFinding, PackageInfo, VersionMetadata

def test_lazy_verification_default_fast_mode():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="PyPI")
    finding = VulnerabilityFinding(cve_id="CVE-2023-0001", package=pkg, fix_version="5.1.15", cvss_severity="HIGH")
    vm = MagicMock(latest_stable_version="6.0.0", latest_version="6.0.0")

    with patch("pulse.version_intelligence.recommendation_engine.UpgradeVerificationService") as mock_service:
        rec = analyze_upgrade_recommendation(
            pkg_name="Django",
            ecosystem="PyPI",
            current_version="3.2",
            findings=[finding],
            version_metadata=vm,
            verify_candidate=False
        )

        assert rec.evidence.method == RecommendationMethod.ADVISORY_CONFIRMED
        assert not rec.verification_scan_performed
        mock_service.assert_not_called()

def test_lazy_verification_on_demand_trigger():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="PyPI")
    finding = VulnerabilityFinding(cve_id="CVE-2023-0001", package=pkg, fix_version="5.1.15", cvss_severity="HIGH")
    vm = MagicMock(latest_stable_version="6.0.0", latest_version="6.0.0")

    mock_res = MagicMock(blocking_findings=0, total_findings=0, cache_hit=False)

    with patch("pulse.version_intelligence.recommendation_engine.UpgradeVerificationService") as mock_service_cls:
        mock_service_cls.return_value.verify_candidate.return_value = mock_res
        rec = analyze_upgrade_recommendation(
            pkg_name="Django",
            ecosystem="PyPI",
            current_version="3.2",
            findings=[finding],
            version_metadata=vm,
            verify_candidate=True
        )

        assert rec.evidence.method == RecommendationMethod.VERIFIED_SCAN
        assert rec.verification_scan_performed
        assert rec.verified_safe
        mock_service_cls.return_value.verify_candidate.assert_called_once()
