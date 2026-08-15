"""
End-to-end correlation consistency tests.

Validates that the UI, report builder, and correlation engine all agree
on the status of technologies by using the single stored eligibility dict.
"""

import pytest
from datetime import datetime
from pulse.domain.models import (
    ScanResult, WebsiteAssessment, TechnologyFingerprint,
    TechnologyCategory, CorrelationStatus
)
from pulse.website.capability import (
    evaluate_correlation_eligibility,
    CorrelationEligibilityStatus,
    evaluate_all_eligibilities
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_scan() -> ScanResult:
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=0,
        attack_surface_score=0,
    )
    scan.website_assessment = WebsiteAssessment(
        url="https://example.com",
        technologies=[
            TechnologyFingerprint(
                name="bootstrap",
                version="5.3.0",
                category=TechnologyCategory.UI_LIBRARY,
                confidence=100,
                signature_id="bootstrap",
                correlation_supported=True,
            ),
            TechnologyFingerprint(
                name="nginx",
                version="1.24.0",
                category=TechnologyCategory.SERVER,
                confidence=95,
                signature_id="nginx",
                correlation_supported=True,
            ),
            TechnologyFingerprint(
                name="unknown_analytics",
                version=None,
                category=TechnologyCategory.ANALYTICS,
                confidence=80,
                signature_id="unknown_analytics",
                correlation_supported=False,
            )
        ]
    )
    # Pre-populate eligibilities as the correlation service would
    scan.website_assessment.technology_eligibilities = evaluate_all_eligibilities(
        scan.website_assessment.technologies
    )
    return scan


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWebCorrelationConsistency:

    def test_ui_coverage_matches_correlation_eligibility(self):
        """Verify the logic used in UI coverage matches the stored eligibilities."""
        scan = _make_mock_scan()
        wa = scan.website_assessment
        eligibilities = wa.technology_eligibilities

        # Mimic UI logic
        elig_values = list(eligibilities.values())
        count_correlatable = sum(1 for e in elig_values if e.status == CorrelationEligibilityStatus.CORRELATABLE)
        count_partial = sum(1 for e in elig_values if e.status == CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE)
        count_detection = sum(1 for e in elig_values if e.status == CorrelationEligibilityStatus.DETECTION_ONLY)

        assert count_correlatable + count_partial > 0
        assert count_detection == 1  # unknown_analytics is detection only

    def test_report_coverage_matches_correlation_eligibility(self):
        """Verify the reporting builder maps eligibility to the correct correlated flag."""
        scan = _make_mock_scan()
        wa = scan.website_assessment
        eligibilities = wa.technology_eligibilities

        for tech in wa.technologies:
            tech_id = getattr(tech, "signature_id", "") or tech.name.lower()
            elig = eligibilities.get(tech_id)
            
            # Mimic Builder logic
            is_correlated = elig.status in (
                CorrelationEligibilityStatus.CORRELATABLE,
                CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
            )
            
            if tech.name == "unknown_analytics":
                assert is_correlated is False
            else:
                assert is_correlated is True

    def test_signature_and_catalog_cannot_disagree(self):
        """If a technology cannot be resolved via package identity or catalog or CPE,
        it must resolve to CORRELATION_UNAVAILABLE or RESOLUTION_FAILED safely,
        never falsely claimed as correlatable."""
        fp = TechnologyFingerprint(
            name="completely_unknown_nonexistent_framework_xyz",
            version="1.0.0",
            category=TechnologyCategory.FRAMEWORK,
            confidence=100,
            signature_id="completely_unknown_nonexistent_framework_xyz",
            correlation_supported=True,
        )
        
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status in (
            CorrelationEligibilityStatus.CORRELATION_UNAVAILABLE,
            CorrelationEligibilityStatus.RESOLUTION_FAILED
        )
        assert elig.is_eligible is False


# ---------------------------------------------------------------------------
# M9.5.x Canonical Website Technology -> Package Vulnerability Correlation
# ---------------------------------------------------------------------------

class DummyConsole:
    def print(self, *args, **kwargs):
        pass


class TestCanonicalWebsitePackageCorrelation:

    def test_package_identity_resolution(self):
        """Test canonical package identity resolver for common web technologies."""
        from pulse.ecosystems.package_identity import resolve_technology_package

        # jQuery
        id_jquery = resolve_technology_package("jQuery", "1.7.2")
        assert id_jquery is not None
        assert id_jquery.name.lower() == "jquery"
        assert id_jquery.ecosystem in ("Node.js", "npm")
        assert id_jquery.version == "1.7.2"

        # Bootstrap
        id_bs = resolve_technology_package("Bootstrap", "4.5.2")
        assert id_bs is not None
        assert id_bs.name.lower() == "bootstrap"
        assert id_bs.ecosystem in ("Node.js", "npm")

        # React
        id_react = resolve_technology_package("React", "18.2.0")
        assert id_react is not None
        assert id_react.name.lower() == "react"
        assert id_react.ecosystem in ("Node.js", "npm")

        # Django
        id_django = resolve_technology_package("Django", "4.2.1")
        assert id_django is not None
        assert id_django.name.lower() == "django"
        assert id_django.ecosystem in ("Python", "PyPI")

        # Rails
        id_rails = resolve_technology_package("Rails", "6.1.0")
        assert id_rails is not None
        assert id_rails.name.lower() == "rails"
        assert id_rails.ecosystem in ("Ruby", "RubyGems")

    def test_website_jquery_correlation_finds_cve_2020_11023(self):
        """Test 1: Website scan detecting jQuery 1.7.2 finds vulnerabilities including CVE-2020-11023."""
        from pulse.services.website_service import WebsiteService
        console = DummyConsole()
        ws = WebsiteService()

        fp_jquery = TechnologyFingerprint(
            name="jQuery",
            version="1.7.2",
            category=TechnologyCategory.UI_LIBRARY,
            confidence=90
        )

        scan = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            packages_scanned=0,
            attack_surface_score=0,
            target_type="website",
            target_id="https://example.com",
            website_assessment=WebsiteAssessment(
                url="https://example.com",
                technologies=[fp_jquery]
            )
        )

        ws.analyze_technologies(console, scan)

        wa = scan.website_assessment
        assert wa.correlated_technologies >= 1
        assert "jQuery" in wa.technology_correlation_results
        corr_res = wa.technology_correlation_results["jQuery"]

        assert corr_res.correlation_status == "VULNERABILITIES_FOUND"
        assert corr_res.package_name == "jquery"
        assert corr_res.ecosystem in ("Node.js", "npm")
        assert len(corr_res.vulnerabilities) > 0

        cve_ids = [f.cve_id for f in corr_res.vulnerabilities]
        assert "CVE-2020-11023" in cve_ids
        assert any(f.cve_id == "CVE-2020-11023" for f in scan.findings)

    def test_package_and_website_parity(self):
        """Test 2: Assert standalone package scan and website correlation produce identical CVE IDs."""
        from pulse.services.package_service import PackageService
        from pulse.services.website_service import WebsiteService
        from pulse.domain.models import PackageInfo

        console = DummyConsole()

        # 1. Run standalone package scan
        ps = PackageService()
        pkg = PackageInfo(name="jquery", version="1.7.2", ecosystem="Node.js")
        pkg_scan = ps.run(console, [pkg], target_type="package", target_id="Node.js:jquery")
        pkg_cves = sorted(list(set(f.cve_id for f in pkg_scan.findings)))

        # 2. Run website scan
        ws = WebsiteService()
        fp_jquery = TechnologyFingerprint(
            name="jQuery",
            version="1.7.2",
            category=TechnologyCategory.UI_LIBRARY,
            confidence=90
        )
        web_scan = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            packages_scanned=0,
            attack_surface_score=0,
            target_type="website",
            target_id="https://example.com",
            website_assessment=WebsiteAssessment(
                url="https://example.com",
                technologies=[fp_jquery]
            )
        )
        ws.analyze_technologies(console, web_scan)
        web_cves = sorted(list(set(f.cve_id for f in web_scan.findings)))

        # Parity check
        assert pkg_cves == web_cves
        assert "CVE-2020-11023" in web_cves

    def test_website_bootstrap_and_react(self):
        """Test 3 & 4: Bootstrap and React correlation via shared pipeline."""
        from pulse.services.website_service import WebsiteService

        console = DummyConsole()
        ws = WebsiteService()

        fp_bs = TechnologyFingerprint(
            name="Bootstrap",
            version="4.5.2",
            category=TechnologyCategory.FRAMEWORK,
            confidence=95
        )
        fp_react = TechnologyFingerprint(
            name="React",
            version="18.2.0",
            category=TechnologyCategory.FRAMEWORK,
            confidence=95
        )

        scan = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            packages_scanned=0,
            attack_surface_score=0,
            target_type="website",
            target_id="https://example.com",
            website_assessment=WebsiteAssessment(
                url="https://example.com",
                technologies=[fp_bs, fp_react]
            )
        )

        ws.analyze_technologies(console, scan)

        wa = scan.website_assessment
        assert "Bootstrap" in wa.technology_correlation_results
        assert "React" in wa.technology_correlation_results
        assert wa.technology_correlation_results["Bootstrap"].ecosystem in ("Node.js", "npm")
        assert wa.technology_correlation_results["React"].ecosystem in ("Node.js", "npm")

    def test_website_deduplication_single_pipeline_run(self):
        """Test: Multiple instances of the same package are deduplicated into ONE unique package."""
        from pulse.services.website_service import WebsiteService

        ws = WebsiteService()

        fp1 = TechnologyFingerprint(name="jQuery", version="1.7.2", category=TechnologyCategory.UI_LIBRARY, confidence=90)
        fp2 = TechnologyFingerprint(name="jquery", version="1.7.2", category=TechnologyCategory.UI_LIBRARY, confidence=80)
        fp3 = TechnologyFingerprint(name="jQuery", version="1.7.2", category=TechnologyCategory.UI_LIBRARY, confidence=70)
        fp4 = TechnologyFingerprint(name="React", version="18.2.0", category=TechnologyCategory.FRAMEWORK, confidence=90)

        normalized = ws._normalize_technologies([fp1, fp2, fp3, fp4])
        eligibilities, tech_to_identity = ws._resolve_package_identities(normalized)
        unique_packages, tech_to_package_key = ws._build_unique_package_infos(normalized, eligibilities, tech_to_identity)

        assert len(unique_packages) == 2
        pkg_names = sorted([p.name.lower() for p in unique_packages])
        assert pkg_names == ["jquery", "react"]

    def test_unknown_technology_safety_state(self):
        """Test: Unknown technology produces CORRELATION_UNAVAILABLE, never 0 vulnerabilities."""
        from pulse.services.website_service import WebsiteService

        console = DummyConsole()
        ws = WebsiteService()

        fp_unknown = TechnologyFingerprint(
            name="NonExistentWebTool99999",
            version="1.0.0",
            category=TechnologyCategory.FRAMEWORK,
            confidence=60
        )

        scan = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            packages_scanned=0,
            attack_surface_score=0,
            target_type="website",
            target_id="https://example.com",
            website_assessment=WebsiteAssessment(
                url="https://example.com",
                technologies=[fp_unknown]
            )
        )

        ws.analyze_technologies(console, scan)

        wa = scan.website_assessment
        assert "NonExistentWebTool99999" in wa.technology_correlation_results
        res = wa.technology_correlation_results["NonExistentWebTool99999"]
        assert res.correlation_status == "CORRELATION_UNAVAILABLE"
        assert len(res.vulnerabilities) == 0

    def test_missing_version_state(self):
        """Test: Missing version produces VERSION_REQUIRED."""
        from pulse.services.website_service import WebsiteService

        console = DummyConsole()
        ws = WebsiteService()

        fp_jquery_no_ver = TechnologyFingerprint(
            name="jQuery",
            version=None,
            category=TechnologyCategory.UI_LIBRARY,
            confidence=90
        )

        scan = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            packages_scanned=0,
            attack_surface_score=0,
            target_type="website",
            target_id="https://example.com",
            website_assessment=WebsiteAssessment(
                url="https://example.com",
                technologies=[fp_jquery_no_ver]
            )
        )

        ws.analyze_technologies(console, scan)

        wa = scan.website_assessment
        assert "jQuery" in wa.technology_correlation_results
        res = wa.technology_correlation_results["jQuery"]
        assert res.correlation_status == "VERSION_REQUIRED"
        assert "Version required" in res.correlation_reason

    def test_offline_mode_identity_resolution(self):
        """Test: Offline mode still resolves known package identities locally."""
        from pulse.ecosystems.package_identity import resolve_technology_package
        from pulse.state import AppState

        AppState.OFFLINE_MODE = True
        try:
            id_django = resolve_technology_package("Django", "4.2.1")
            assert id_django is not None
            assert id_django.name.lower() == "django"
            assert id_django.ecosystem in ("Python", "PyPI")

            id_jquery = resolve_technology_package("jQuery", "1.7.2")
            assert id_jquery is not None
            assert id_jquery.name.lower() == "jquery"
            assert id_jquery.ecosystem in ("Node.js", "npm")
        finally:
            AppState.OFFLINE_MODE = False

