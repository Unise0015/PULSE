"""
Tests for the capability registry: validate_technology_capabilities() and
ProviderCapability data model.
"""

import pytest
from pulse.website.capability import (
    validate_technology_capabilities,
    ProviderCapability,
    CorrelationEligibilityStatus,
    evaluate_correlation_eligibility,
    _determine_provider_capabilities,
    _resolve_via_catalog,
    _resolve_via_fingerprint,
    _lookup_strategy_from_caps,
)
from pulse.domain.models import TechnologyFingerprint, TechnologyCategory, CPECandidate


# ---------------------------------------------------------------------------
# ProviderCapability
# ---------------------------------------------------------------------------

class TestProviderCapability:
    def test_osv_capability(self):
        cap = ProviderCapability(
            provider="OSV",
            supported=True,
            ecosystem="npm",
            package="bootstrap",
        )
        assert cap.provider == "OSV"
        assert cap.supported is True
        assert cap.ecosystem == "npm"

    def test_nvd_capability(self):
        cap = ProviderCapability(
            provider="NVD",
            supported=True,
            cpe_vendor="getbootstrap",
            cpe_product="bootstrap",
        )
        assert cap.provider == "NVD"
        assert cap.cpe_vendor == "getbootstrap"

    def test_unsupported_capability(self):
        cap = ProviderCapability(provider="OSV", supported=False)
        assert cap.supported is False


# ---------------------------------------------------------------------------
# Catalog Resolution
# ---------------------------------------------------------------------------

class TestCatalogResolution:
    def test_exact_match(self):
        result = _resolve_via_catalog("jquery")
        assert result is not None
        assert result["key"] == "jquery"

    def test_alias_match(self):
        result = _resolve_via_catalog("reactjs")
        assert result is not None
        assert result["key"] == "react"

    def test_case_insensitive(self):
        result = _resolve_via_catalog("WordPress")
        assert result is not None
        assert result["key"] == "wordpress"

    def test_missing(self):
        result = _resolve_via_catalog("nonexistent_technology_xyz")
        assert result is None


# ---------------------------------------------------------------------------
# Fingerprint-Level Identity Resolution
# ---------------------------------------------------------------------------

class TestFingerprintResolution:
    def test_ecosystem_from_fingerprint(self):
        fp = TechnologyFingerprint(
            name="custom_lib",
            version="1.0.0",
            category=TechnologyCategory.UI_LIBRARY,
            ecosystem="npm",
        )
        result = _resolve_via_fingerprint(fp)
        assert result["ecosystem"] == "npm"

    def test_cpe_from_fingerprint(self):
        fp = TechnologyFingerprint(
            name="custom_lib",
            version="1.0.0",
            category=TechnologyCategory.UI_LIBRARY,
            cpe_candidates=[
                CPECandidate(cpe="cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", confidence=90)
            ],
        )
        result = _resolve_via_fingerprint(fp)
        assert result["cpe_vendor"] == "vendor"
        assert result["cpe_product"] == "product"


# ---------------------------------------------------------------------------
# Provider Capabilities Determination
# ---------------------------------------------------------------------------

class TestDetermineProviderCapabilities:
    def test_both_sources(self):
        caps = _determine_provider_capabilities("npm", "jquery", "jquery", "jquery")
        providers = [c.provider for c in caps]
        assert "OSV" in providers
        assert "NVD" in providers
        assert "EPSS" in providers
        assert "KEV" in providers

    def test_osv_only(self):
        caps = _determine_provider_capabilities("npm", "jquery", None, None)
        providers = [c.provider for c in caps]
        assert "OSV" in providers
        assert "NVD" not in providers

    def test_nvd_only(self):
        caps = _determine_provider_capabilities(None, None, "apache", "http_server")
        providers = [c.provider for c in caps]
        assert "NVD" in providers
        assert "OSV" not in providers

    def test_no_sources(self):
        caps = _determine_provider_capabilities(None, None, None, None)
        assert len(caps) == 0


# ---------------------------------------------------------------------------
# Lookup Strategy From Caps
# ---------------------------------------------------------------------------

class TestLookupStrategy:
    def test_both(self):
        caps = [
            ProviderCapability(provider="OSV", supported=True, ecosystem="npm", package="x"),
            ProviderCapability(provider="NVD", supported=True, cpe_vendor="v", cpe_product="p"),
        ]
        assert _lookup_strategy_from_caps(caps) == "both"

    def test_osv_only(self):
        caps = [
            ProviderCapability(provider="OSV", supported=True, ecosystem="npm", package="x"),
        ]
        assert _lookup_strategy_from_caps(caps) == "osv"

    def test_nvd_only(self):
        caps = [
            ProviderCapability(provider="NVD", supported=True, cpe_vendor="v", cpe_product="p"),
        ]
        assert _lookup_strategy_from_caps(caps) == "nvd"

    def test_none(self):
        assert _lookup_strategy_from_caps([]) is None


# ---------------------------------------------------------------------------
# Validate Technology Capabilities (Diagnostic)
# ---------------------------------------------------------------------------

class TestValidateTechnologyCapabilities:
    def test_runs_without_error(self):
        """Should not raise even if some signatures have issues."""
        diagnostics = validate_technology_capabilities()
        assert isinstance(diagnostics, list)

    def test_known_correlatable_techs_pass(self):
        """All known correlatable signatures should produce ✓ or ⚠, never ✗."""
        diagnostics = validate_technology_capabilities()
        errors = [d for d in diagnostics if d.startswith("\u2717")]
        # With catalog entries for bootstrap and tailwind, no errors expected
        assert len(errors) == 0, f"Capability errors found: {errors}"

    def test_output_contains_known_techs(self):
        """Output should mention known correlatable technologies."""
        diagnostics = validate_technology_capabilities()
        all_text = " ".join(diagnostics)
        # At least some known techs should appear
        assert "jquery" in all_text.lower() or "bootstrap" in all_text.lower()
