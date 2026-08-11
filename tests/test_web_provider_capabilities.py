"""
Tests for provider capabilities and coverage.

Validates that missing one provider (like OSV) doesn't prevent correlation via
another (like NVD) and that partial coverage is correctly reflected.
"""

import pytest
from pulse.website.capability import (
    evaluate_correlation_eligibility,
    CorrelationEligibilityStatus,
)
from pulse.domain.models import TechnologyFingerprint, TechnologyCategory


class TestWebProviderCapabilities:

    def test_osv_only_capability(self):
        """A technology with only ecosystem/package (OSV) should be Correlatable/Partial."""
        # Using a mock technology that would only have ecosystem
        fp = TechnologyFingerprint(
            name="mock_npm_lib",
            version="1.0.0",
            category=TechnologyCategory.UI_LIBRARY,
            confidence=100,
            signature_id="mock_npm_lib",
            correlation_supported=True,
            ecosystem="npm",
        )
        elig = evaluate_correlation_eligibility(fp)
        
        # It's not in the catalog, but it has ecosystem -> OSV is supported
        assert "OSV" in elig.intelligence_sources
        assert "NVD" not in elig.intelligence_sources
        
        # Should be partially correlatable because only 1 primary provider is available
        assert elig.status == CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE

    def test_nvd_only_capability(self):
        """A technology with only NVD CPEs should be Correlatable/Partial."""
        # Nginx only has NVD correlation usually
        fp = TechnologyFingerprint(
            name="nginx",
            version="1.24.0",
            category=TechnologyCategory.SERVER,
            confidence=100,
            signature_id="nginx",
            correlation_supported=True,
        )
        elig = evaluate_correlation_eligibility(fp)
        
        assert "NVD" in elig.intelligence_sources
        assert "OSV" not in elig.intelligence_sources
        
        # Should be partially correlatable
        assert elig.status == CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE

    def test_full_capability(self):
        """A technology with both OSV and NVD and full coverage should be fully CORRELATABLE."""
        fp = TechnologyFingerprint(
            name="next.js",
            version="13.4.0",
            category=TechnologyCategory.FRAMEWORK,
            confidence=100,
            signature_id="nextjs",
            correlation_supported=True,
        )
        elig = evaluate_correlation_eligibility(fp)
        
        assert "OSV" in elig.intelligence_sources
        assert "NVD" in elig.intelligence_sources
        
        assert elig.status == CorrelationEligibilityStatus.CORRELATABLE
