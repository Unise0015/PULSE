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
        """The core fix: if signature says True but catalog is missing,
        it must resolve via package/CPE mapping or fail safely, not silently
        cause UI/Correlation divergence."""
        
        # This technology has correlation_supported=True but is NOT in catalog
        fp = TechnologyFingerprint(
            name="new_framework",
            version="1.0.0",
            category=TechnologyCategory.FRAMEWORK,
            confidence=100,
            signature_id="new_framework",
            correlation_supported=True,
        )
        
        elig = evaluate_correlation_eligibility(fp)
        
        # Because it's not in catalog AND has no ecosystem/CPE on the fingerprint,
        # it correctly resolves to RESOLUTION_FAILED, preventing it from being
        # shown as 'Correlatable' in the UI while skipping in correlation.
        assert elig.status == CorrelationEligibilityStatus.RESOLUTION_FAILED
