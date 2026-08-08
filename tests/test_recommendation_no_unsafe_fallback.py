import pytest
from pulse.domain.models import VulnerabilityFinding, PackageInfo
from pulse.version_intelligence.recommendation_engine import analyze_upgrade_recommendation


class TestRecommendationNoUnsafeFallback:
    """Component 5 & Bug 8, 9, 22 – Tests that vulnerable current versions are never recommended and no unsafe upgrade command is emitted."""

    def test_vulnerable_current_version_never_recommended(self):
        pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")
        finding = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2022-34265",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            description="SQL Injection in Django"
        )

        # Case 1: Unknown latest stable and no known minimum safe version
        rec = analyze_upgrade_recommendation(
            pkg_name="Django",
            ecosystem="pypi",
            current_version="3.2",
            findings=[finding],
            version_metadata=None,
            verify_candidate=False
        )

        # Assert: recommended_version MUST NOT be "3.2"
        assert rec.recommended_version != "3.2", "Vulnerable version '3.2' must never be recommended"
        assert rec.recommended_version is None
        assert "Manual upgrade review required" in rec.upgrade_command

    def test_unknown_latest_stable_does_not_cause_unsafe_fallback(self):
        pkg = PackageInfo(name="flask", version="0.12.0", ecosystem="pypi")
        finding = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2018-1000656",
            cvss_score=7.5,
            cvss_severity="HIGH",
            description="Denial of Service in Flask"
        )

        rec = analyze_upgrade_recommendation(
            pkg_name="flask",
            ecosystem="pypi",
            current_version="0.12.0",
            findings=[finding],
            version_metadata=None
        )

        assert rec.recommended_version is None or rec.recommended_version != "0.12.0"
        assert rec.latest_stable is None
        assert "pip install flask==0.12.0" not in rec.upgrade_command

    def test_safe_package_with_no_vulnerabilities_retains_current(self):
        pkg = PackageInfo(name="requests", version="2.31.0", ecosystem="pypi")

        rec = analyze_upgrade_recommendation(
            pkg_name="requests",
            ecosystem="pypi",
            current_version="2.31.0",
            findings=[],
            version_metadata=None
        )

        assert rec.recommended_version == "2.31.0"
        assert "pip install requests==2.31.0" in rec.upgrade_command
