"""Tests for M10.2.4 – NVD Correlation Engine.

Covers:
    - Exact version matching
    - Range version matching
    - Version mismatch (no false positives)
    - Candidate fallback resolution
    - Cache hit tracking
    - Minimum confidence threshold filtering
    - Version-specific cache key isolation
    - Correlation provenance preservation
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from pulse.correlation.models import (
    CPECandidate,
    CorrelationResult,
    ResolverMatchType,
)
from pulse.enrichment.nvd.models import (
    CorrelatedVulnerability,
    NVDCorrelationStatistics,
    VersionMatchType,
)
from pulse.enrichment.nvd.matcher import NVDVersionMatcher
from pulse.enrichment.nvd.cache import NVDCorrelationCache
from pulse.enrichment.nvd.statistics import NVDStatisticsTracker
from pulse.enrichment.nvd.correlator import NVDCorrelationEngine


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_candidate(
    vendor="vercel",
    product="next.js",
    version="15.0",
    confidence=90,
    cpe_template="cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
    match_type=ResolverMatchType.EXACT,
) -> CPECandidate:
    return CPECandidate(
        cpe_template=cpe_template,
        detected_version=version,
        resolved_cpe=None,
        confidence=confidence,
        source="nextjs_resolver",
        vendor=vendor,
        product=product,
        exact_version_match=True,
        match_type=match_type,
    )


def _make_cve(
    cve_id="CVE-2024-1234",
    vendor="vercel",
    product="next.js",
    version="15.0",
    range_start=None,
    range_end=None,
    wildcard=False,
) -> dict:
    """Build a mock NVD CVE record with configurations."""
    if wildcard:
        cpe_version = "*"
    elif version:
        cpe_version = version
    else:
        cpe_version = "*"

    cpe_match = {
        "vulnerable": True,
        "criteria": f"cpe:2.3:a:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*",
    }

    if range_start:
        cpe_match["versionStartIncluding"] = range_start
        cpe_match["criteria"] = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
    if range_end:
        cpe_match["versionEndExcluding"] = range_end
        cpe_match["criteria"] = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"

    return {
        "id": cve_id,
        "published": "2024-01-15T00:00:00Z",
        "descriptions": [
            {"lang": "en", "value": f"Test vulnerability in {product}"}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [cpe_match],
                    }
                ]
            }
        ],
    }


def _make_result(
    candidate=None,
    candidates=None,
    technology="Next.js",
    key="next.js",
    confidence=90,
) -> CorrelationResult:
    if candidate is None:
        candidate = _make_candidate(confidence=confidence)
    if candidates is None:
        candidates = [candidate]
    return CorrelationResult(
        technology=technology,
        inventory_technology_key=key,
        candidates=candidates,
        selected_candidate=candidate,
        resolution_confidence=confidence,
    )


# ── Version Matcher Tests ────────────────────────────────────────────────────

class TestNVDVersionMatcher:

    def setup_method(self):
        self.matcher = NVDVersionMatcher()

    def test_exact_version_match(self):
        """Detected 15.0 vs affected exactly 15.0 → EXACT match."""
        cve = _make_cve(version="15.0")
        match_type, confidence = self.matcher.match_version(
            "15.0", cve, "vercel", "next.js"
        )
        assert match_type == VersionMatchType.EXACT
        assert confidence == 100

    def test_range_version_match(self):
        """Detected 15.0 vs affected >=14.0, <16.0 → RANGE match."""
        cve = _make_cve(range_start="14.0", range_end="16.0")
        match_type, confidence = self.matcher.match_version(
            "15.0", cve, "vercel", "next.js"
        )
        assert match_type == VersionMatchType.RANGE
        assert confidence == 90

    def test_version_mismatch(self):
        """Detected 15.0 vs affected <14.0 → no match."""
        cve = _make_cve(range_end="14.0")
        match_type, confidence = self.matcher.match_version(
            "15.0", cve, "vercel", "next.js"
        )
        # Should be PARTIAL with 0 confidence (mismatch)
        assert confidence == 0

    def test_wildcard_version(self):
        """Wildcard CPE version → PARTIAL match."""
        cve = _make_cve(wildcard=True)
        match_type, confidence = self.matcher.match_version(
            "15.0", cve, "vercel", "next.js"
        )
        assert match_type == VersionMatchType.PARTIAL
        assert confidence == 70

    def test_no_detected_version(self):
        """No detected version → UNKNOWN_VERSION."""
        cve = _make_cve(version="15.0")
        match_type, confidence = self.matcher.match_version(
            None, cve, "vercel", "next.js"
        )
        assert match_type == VersionMatchType.UNKNOWN_VERSION
        assert confidence == 40

    def test_no_configurations(self):
        """CVE with no configurations → PARTIAL match (CPE matched but no ranges)."""
        cve = {"id": "CVE-2024-9999", "configurations": []}
        match_type, confidence = self.matcher.match_version(
            "15.0", cve, "vercel", "next.js"
        )
        assert match_type == VersionMatchType.PARTIAL
        assert confidence == 70

    def test_vendor_product_mismatch_ignored(self):
        """CPE for different vendor/product is skipped."""
        cve = _make_cve(vendor="apache", product="httpd", version="2.4.51")
        match_type, confidence = self.matcher.match_version(
            "15.0", cve, "vercel", "next.js"
        )
        assert confidence == 0


# ── Cache Tests ──────────────────────────────────────────────────────────────

class TestNVDCorrelationCache:

    def test_version_specific_cache_key(self):
        """Next.js 14 and Next.js 15 must generate different cache keys."""
        cpe = "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"
        key_14 = NVDCorrelationCache.make_key(cpe, "14.0")
        key_15 = NVDCorrelationCache.make_key(cpe, "15.0")
        assert key_14 != key_15

    def test_same_version_same_key(self):
        """Same CPE + same version → same cache key."""
        cpe = "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"
        key1 = NVDCorrelationCache.make_key(cpe, "15.0")
        key2 = NVDCorrelationCache.make_key(cpe, "15.0")
        assert key1 == key2

    def test_no_version_key(self):
        """No detected version produces a stable key different from versioned keys."""
        cpe = "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"
        key_none = NVDCorrelationCache.make_key(cpe, None)
        key_15 = NVDCorrelationCache.make_key(cpe, "15.0")
        assert key_none != key_15


# ── Statistics Tracker Tests ─────────────────────────────────────────────────

class TestNVDStatisticsTracker:

    def test_accumulation(self):
        tracker = NVDStatisticsTracker()
        tracker.record_cpe_processed()
        tracker.record_cpe_processed()
        tracker.record_cves_retrieved(5)
        tracker.record_version_match()
        tracker.record_version_mismatch()
        tracker.record_correlated_vulnerability()
        tracker.record_cache_hit()
        tracker.record_fallback_attempt()
        tracker.record_below_threshold()

        stats = tracker.finalize()
        assert stats.cpes_processed == 2
        assert stats.cves_retrieved == 5
        assert stats.version_matches == 1
        assert stats.version_mismatches == 1
        assert stats.correlated_vulnerabilities == 1
        assert stats.cache_hits == 1
        assert stats.fallback_attempts == 1
        assert stats.below_threshold_filtered == 1

    def test_finalize_is_snapshot(self):
        """Finalize returns a copy, not a mutable reference."""
        tracker = NVDStatisticsTracker()
        tracker.record_cpe_processed()
        stats = tracker.finalize()
        tracker.record_cpe_processed()
        assert stats.cpes_processed == 1  # original snapshot unchanged


# ── Correlator Engine Tests ──────────────────────────────────────────────────

class TestNVDCorrelationEngine:

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_exact_version_correlation(self, MockCache, MockProvider):
        """Exact version match produces a high-confidence finding."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None  # cache miss

        cve = _make_cve(cve_id="CVE-2024-1001", version="15.0")
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        result = _make_result(confidence=90)
        findings, stats = engine.correlate([result])

        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-1001"
        assert findings[0].version_match_type == VersionMatchType.EXACT
        # confidence = 0.5 * 90 (candidate) + 0.5 * 100 (exact) = 95
        assert findings[0].confidence == 95
        assert stats.correlated_vulnerabilities == 1

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_range_version_correlation(self, MockCache, MockProvider):
        """Range version match produces correct match type."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        cve = _make_cve(cve_id="CVE-2024-1002", range_start="14.0", range_end="16.0")
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        result = _make_result(confidence=90)
        findings, stats = engine.correlate([result])

        assert len(findings) == 1
        assert findings[0].version_match_type == VersionMatchType.RANGE
        # confidence = 0.5 * 90 + 0.5 * 90 = 90
        assert findings[0].confidence == 90

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_version_mismatch_filtered(self, MockCache, MockProvider):
        """Version mismatch produces no findings."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        cve = _make_cve(cve_id="CVE-2024-1003", range_end="14.0")
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        result = _make_result(confidence=90)
        findings, stats = engine.correlate([result])

        assert len(findings) == 0
        assert stats.version_mismatches == 1

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_fallback_candidate_resolution(self, MockCache, MockProvider):
        """Primary CPE returns no CVEs → falls back to secondary candidate."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        # Primary returns empty, secondary returns a hit
        secondary_cve = _make_cve(
            cve_id="CVE-2024-2001",
            vendor="vercel",
            product="next.js",
            version="15.0",
        )
        mock_provider.fetch_cves_by_cpe.side_effect = [[], [secondary_cve]]

        primary = _make_candidate(
            confidence=90,
            cpe_template="cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
        )
        secondary = _make_candidate(
            confidence=60,
            cpe_template="cpe:2.3:a:vercel:nextjs:*:*:*:*:*:*:*:*",
        )
        result = CorrelationResult(
            technology="Next.js",
            inventory_technology_key="next.js",
            candidates=[primary, secondary],
            selected_candidate=primary,
            resolution_confidence=90,
        )

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        findings, stats = engine.correlate([result])

        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-2001"
        assert stats.fallback_attempts == 1

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_cache_hit_tracking(self, MockCache, MockProvider):
        """Cached CVE data is reused and tracked in statistics."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value

        cached_cve = _make_cve(cve_id="CVE-2024-3001", version="15.0")
        mock_cache.get.return_value = [cached_cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        result = _make_result(confidence=90)
        findings, stats = engine.correlate([result])

        assert len(findings) == 1
        assert stats.cache_hits == 1
        mock_provider.fetch_cves_by_cpe.assert_not_called()

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_minimum_confidence_threshold(self, MockCache, MockProvider):
        """Low-confidence correlations are filtered out."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        # Wildcard CVE → PARTIAL (70) with a low-confidence candidate (30)
        cve = _make_cve(cve_id="CVE-2024-4001", wildcard=True)
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        low_candidate = _make_candidate(confidence=30)
        result = _make_result(candidate=low_candidate, confidence=30)
        findings, stats = engine.correlate([result])

        # confidence = 0.5 * 30 + 0.5 * 70 = 50 → exactly at threshold
        assert len(findings) == 1  # threshold is 50, score is exactly 50

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_below_threshold_filtered(self, MockCache, MockProvider):
        """Findings below 50 confidence are suppressed."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        # UNKNOWN_VERSION (40) with a low-confidence candidate (20)
        cve = _make_cve(cve_id="CVE-2024-4002", version="15.0")
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        low_candidate = _make_candidate(confidence=20, version=None)
        result = _make_result(candidate=low_candidate, confidence=20)
        findings, stats = engine.correlate([result])

        # confidence = 0.5 * 20 + 0.5 * 40 = 30 → below threshold
        assert len(findings) == 0
        assert stats.below_threshold_filtered == 1

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_correlation_provenance(self, MockCache, MockProvider):
        """Verify matched_cpe, correlation_source, version_match_type are preserved."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        cve = _make_cve(cve_id="CVE-2024-5001", version="15.0")
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        result = _make_result(confidence=96)
        findings, stats = engine.correlate([result])

        assert len(findings) == 1
        f = findings[0]

        # Provenance fields
        assert f.correlation_source == "cpe:2.3:a:vercel:next.js"
        assert f.candidate_confidence == 96
        assert f.source_cpe == "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"
        assert f.matched_cpe is not None
        assert "vercel" in f.matched_cpe
        assert f.version_match_type == VersionMatchType.EXACT
        assert f.technology_name == "Next.js"
        assert f.matched_version == "15.0"
        assert f.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-5001"

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_cvss_extraction(self, MockCache, MockProvider):
        """CVSS v3.1 score and severity are extracted from NVD metrics."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value
        mock_cache.get.return_value = None

        cve = _make_cve(cve_id="CVE-2024-6001", version="15.0")
        mock_provider.fetch_cves_by_cpe.return_value = [cve]

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        result = _make_result(confidence=90)
        findings, _ = engine.correlate([result])

        assert len(findings) == 1
        assert findings[0].cvss_v3_score == 7.5
        assert findings[0].severity == "HIGH"

    @patch("pulse.enrichment.nvd.correlator.NVDCPEProvider")
    @patch("pulse.enrichment.nvd.correlator.NVDCorrelationCache")
    def test_empty_results_no_crash(self, MockCache, MockProvider):
        """Engine handles empty input gracefully."""
        mock_provider = MockProvider.return_value
        mock_cache = MockCache.return_value

        engine = NVDCorrelationEngine()
        engine.provider = mock_provider
        engine.cache = mock_cache

        findings, stats = engine.correlate([])
        assert findings == []
        assert stats.cpes_processed == 0
