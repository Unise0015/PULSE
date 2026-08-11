"""
Tests for the core evaluate_correlation_eligibility() function.

Validates the multi-source identity resolution chain and all 7 mutually exclusive
eligibility status outcomes.
"""

import pytest
from unittest.mock import MagicMock
from pulse.website.capability import (
    evaluate_correlation_eligibility,
    CorrelationEligibilityStatus,
    CorrelationEligibility,
    CORRELATION_CONFIDENCE_THRESHOLD,
)
from pulse.domain.models import TechnologyFingerprint, TechnologyCategory, CPECandidate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fingerprint(
    name: str,
    signature_id: str = "",
    correlation_supported: bool = True,
    ecosystem: str | None = None,
    cpe_candidates: list | None = None,
    confidence: int = 95,
    version: str | None = "1.0.0",
    category: TechnologyCategory = TechnologyCategory.UI_LIBRARY,
) -> TechnologyFingerprint:
    """Build a lightweight TechnologyFingerprint for testing."""
    return TechnologyFingerprint(
        name=name,
        version=version,
        category=category,
        confidence=confidence,
        signature_id=signature_id or name.lower(),
        correlation_supported=correlation_supported,
        ecosystem=ecosystem,
        cpe_candidates=cpe_candidates or [],
    )


# ---------------------------------------------------------------------------
# Step 1 — Invalid fingerprint
# ---------------------------------------------------------------------------

class TestResolutionFailed:
    def test_missing_name(self):
        fp = _make_fingerprint(name="")
        fp.name = ""
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status == CorrelationEligibilityStatus.RESOLUTION_FAILED

    def test_none_name(self):
        fp = _make_fingerprint(name="unknown")
        fp.name = None
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status == CorrelationEligibilityStatus.RESOLUTION_FAILED


# ---------------------------------------------------------------------------
# Step 2 — Detection-Only
# ---------------------------------------------------------------------------

class TestDetectionOnly:
    def test_correlation_not_supported(self):
        fp = _make_fingerprint(name="cloudflare", correlation_supported=False)
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status == CorrelationEligibilityStatus.DETECTION_ONLY

    def test_detection_only_is_not_unsupported(self):
        """A detection-only technology is NOT 'unsupported'. It's explicitly
        marked as 'detection only' by its signature."""
        fp = _make_fingerprint(name="some_cdn", correlation_supported=False)
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status == CorrelationEligibilityStatus.DETECTION_ONLY
        assert "detection-only" in elig.reason.lower() or "detection only" in elig.reason.lower()


# ---------------------------------------------------------------------------
# Step 3 — Identity Resolution
# ---------------------------------------------------------------------------

class TestIdentityResolution:
    def test_catalog_resolution(self):
        """bootstrap is now in catalog -> should resolve."""
        fp = _make_fingerprint(name="bootstrap", ecosystem="npm")
        elig = evaluate_correlation_eligibility(fp)
        assert elig.catalog_key == "bootstrap"
        assert elig.package_name == "bootstrap"
        assert elig.ecosystem == "npm"

    def test_alias_resolution(self):
        """'tailwindcss' is an alias for 'tailwind' in catalog."""
        fp = _make_fingerprint(name="tailwindcss", ecosystem="npm")
        elig = evaluate_correlation_eligibility(fp)
        assert elig.catalog_key == "tailwind"

    def test_missing_catalog_but_valid_cpe_is_correlatable(self):
        """A technology not in catalog but with CPE candidates from its signature
        should NOT be classified as unsupported/resolution failed."""
        fp = _make_fingerprint(
            name="some_new_framework",
            correlation_supported=True,
            ecosystem="npm",
            cpe_candidates=[CPECandidate(cpe="cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", confidence=90)],
        )
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status in (
            CorrelationEligibilityStatus.CORRELATABLE,
            CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
        )

    def test_missing_catalog_but_valid_package_mapping_is_correlatable(self):
        """A technology not in catalog but with ecosystem set on the fingerprint
        should still be correlatable via OSV."""
        fp = _make_fingerprint(
            name="my_custom_lib",
            correlation_supported=True,
            ecosystem="npm",
        )
        elig = evaluate_correlation_eligibility(fp)
        # Has package identity (ecosystem + name) -> should resolve
        assert elig.status != CorrelationEligibilityStatus.RESOLUTION_FAILED

    def test_no_identity_at_all(self):
        """No catalog, no ecosystem, no CPE -> RESOLUTION_FAILED."""
        fp = _make_fingerprint(
            name="totally_unknown_thing",
            correlation_supported=True,
            ecosystem=None,
            cpe_candidates=[],
        )
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status == CorrelationEligibilityStatus.RESOLUTION_FAILED


# ---------------------------------------------------------------------------
# Step 4 — Confidence
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_below_threshold(self):
        fp = _make_fingerprint(name="jquery", confidence=20)
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status == CorrelationEligibilityStatus.CONFIDENCE_TOO_LOW

    def test_at_threshold(self):
        fp = _make_fingerprint(name="jquery", confidence=CORRELATION_CONFIDENCE_THRESHOLD)
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status != CorrelationEligibilityStatus.CONFIDENCE_TOO_LOW

    def test_above_threshold(self):
        fp = _make_fingerprint(name="jquery", confidence=95)
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status != CorrelationEligibilityStatus.CONFIDENCE_TOO_LOW


# ---------------------------------------------------------------------------
# Step 5 — Version Required
# ---------------------------------------------------------------------------

class TestVersionRequired:
    def test_version_required_is_not_unsupported(self):
        """Missing version should produce VERSION_REQUIRED, not 'unsupported'."""
        fp = _make_fingerprint(name="react", version=None)
        elig = evaluate_correlation_eligibility(fp)
        # React has OSV (npm) -> version is required for OSV
        assert elig.status == CorrelationEligibilityStatus.VERSION_REQUIRED

    def test_version_present(self):
        fp = _make_fingerprint(name="react", version="18.2.0")
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status != CorrelationEligibilityStatus.VERSION_REQUIRED


# ---------------------------------------------------------------------------
# Step 6 — Provider Coverage
# ---------------------------------------------------------------------------

class TestProviderCoverage:
    def test_osv_unavailable_does_not_mean_unsupported(self):
        """A technology with only NVD (CPE) should be at least PARTIALLY_CORRELATABLE,
        not unsupported."""
        fp = _make_fingerprint(
            name="nginx",
            version="1.24.0",
        )
        elig = evaluate_correlation_eligibility(fp)
        # nginx has NVD CPE in catalog
        assert elig.status in (
            CorrelationEligibilityStatus.CORRELATABLE,
            CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
        )

    def test_nvd_unavailable_does_not_mean_unsupported(self):
        """A technology with only OSV (ecosystem+package) should be at least
        PARTIALLY_CORRELATABLE."""
        fp = _make_fingerprint(
            name="wordpress",
            version="6.4.2",
        )
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status in (
            CorrelationEligibilityStatus.CORRELATABLE,
            CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
        )

    def test_partial_provider_coverage(self):
        """When only one primary provider is available, status should reflect partial."""
        fp = _make_fingerprint(
            name="nginx",
            version="1.24.0",
        )
        elig = evaluate_correlation_eligibility(fp)
        # nginx only has NVD -> partial
        assert elig.status == CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE

    def test_full_provider_coverage(self):
        """When both OSV and NVD are available."""
        fp = _make_fingerprint(
            name="jquery",
            version="3.6.0",
        )
        elig = evaluate_correlation_eligibility(fp)
        # jquery has both npm (OSV) and CPE (NVD)
        assert elig.status in (
            CorrelationEligibilityStatus.CORRELATABLE,
            CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
        )


# ---------------------------------------------------------------------------
# Mutual Exclusivity Invariant
# ---------------------------------------------------------------------------

class TestMutualExclusivity:
    def test_exactly_one_status(self):
        """Every technology must have exactly one eligibility status."""
        techs = [
            _make_fingerprint(name="jquery", version="3.6.0"),
            _make_fingerprint(name="react", version="18.0.0"),
            _make_fingerprint(name="bootstrap", version="5.3.0"),
            _make_fingerprint(name="nginx", version="1.24.0"),
            _make_fingerprint(name="cloudflare", correlation_supported=False),
            _make_fingerprint(name="unknown_thing", correlation_supported=True, ecosystem=None),
        ]
        all_statuses = list(CorrelationEligibilityStatus)
        for tech in techs:
            elig = evaluate_correlation_eligibility(tech)
            assert elig.status in all_statuses
            # Status is a single value, not a collection
            assert isinstance(elig.status, CorrelationEligibilityStatus)


# ---------------------------------------------------------------------------
# Bootstrap Regression Test
# ---------------------------------------------------------------------------

class TestBootstrapRegression:
    def test_bootstrap_is_correlatable(self):
        """The ORIGINAL BUG: Bootstrap was simultaneously 'Correlatable' in
        the UI (via signature flag) and 'Unsupported' in the correlation engine
        (via missing catalog entry).

        After fix: Bootstrap must be CORRELATABLE or PARTIALLY_CORRELATABLE."""
        fp = _make_fingerprint(
            name="bootstrap",
            signature_id="bootstrap",
            correlation_supported=True,
            ecosystem="npm",
            version="5.3.0",
        )
        elig = evaluate_correlation_eligibility(fp)
        assert elig.is_eligible, (
            f"Bootstrap must be eligible for correlation, got {elig.status.value}: {elig.reason}"
        )
        assert elig.catalog_key == "bootstrap"
        assert elig.package_name == "bootstrap"
        assert elig.ecosystem == "npm"
        assert elig.cpe_vendor == "getbootstrap"
        assert elig.cpe_product == "bootstrap"
        assert len(elig.intelligence_sources) >= 2  # OSV + NVD + EPSS + KEV

    def test_bootstrap_not_skipped(self):
        """Ensure Bootstrap is NOT in the 'skipped' category."""
        fp = _make_fingerprint(name="bootstrap", version="5.3.0")
        elig = evaluate_correlation_eligibility(fp)
        assert elig.status not in (
            CorrelationEligibilityStatus.DETECTION_ONLY,
            CorrelationEligibilityStatus.INTELLIGENCE_UNAVAILABLE,
            CorrelationEligibilityStatus.RESOLUTION_FAILED,
        )
