import logging
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any

from pulse.correlation.models import CorrelationResult, CPECandidate
from pulse.enrichment.nvd.models import (
    CorrelatedVulnerability,
    NVDCorrelationStatistics,
    VersionMatchType,
)
from pulse.enrichment.nvd.provider import NVDCPEProvider
from pulse.enrichment.nvd.matcher import NVDVersionMatcher
from pulse.enrichment.nvd.cache import NVDCorrelationCache
from pulse.enrichment.nvd.statistics import NVDStatisticsTracker

logger = logging.getLogger(__name__)

_MINIMUM_CONFIDENCE_THRESHOLD = 50


class NVDCorrelationEngine:
    """Correlates resolved CPE candidates against NVD to produce vulnerability findings.
    
    Responsibilities (and nothing more):
        - Candidate selection and fallback ordering
        - Confidence scoring from candidate confidence × version match quality
        - Minimum threshold filtering
        - Finding generation with full provenance
    
    Delegates to:
        - NVDCPEProvider   for API retrieval
        - NVDVersionMatcher for version evaluation
        - NVDCorrelationCache for caching
    """

    def __init__(self, cache_ttl_hours: int = 24):
        self.provider = NVDCPEProvider()
        self.matcher = NVDVersionMatcher()
        self.cache = NVDCorrelationCache(ttl_hours=cache_ttl_hours)

    def correlate(
        self,
        results: List[CorrelationResult]
    ) -> Tuple[List[CorrelatedVulnerability], NVDCorrelationStatistics]:
        """Run NVD correlation for a list of CPE resolution results.
        
        For each CorrelationResult:
            1. Try selected_candidate first.
            2. If no CVEs found, fallback to remaining candidates.
            3. Apply version matching to each retrieved CVE.
            4. Emit findings that exceed the minimum confidence threshold.
        
        Returns (findings, statistics).
        """
        tracker = NVDStatisticsTracker()
        findings: List[CorrelatedVulnerability] = []

        for result in results:
            if not result.selected_candidate and not result.candidates:
                continue

            result_findings = self._correlate_single(result, tracker)
            findings.extend(result_findings)

        return findings, tracker.finalize()

    def _correlate_single(
        self,
        result: CorrelationResult,
        tracker: NVDStatisticsTracker,
    ) -> List[CorrelatedVulnerability]:
        """Correlate a single CorrelationResult against NVD."""
        findings: List[CorrelatedVulnerability] = []

        # Build candidate order: selected first, then remaining by confidence desc
        ordered_candidates = self._build_candidate_order(result)

        for idx, candidate in enumerate(ordered_candidates):
            tracker.record_cpe_processed()

            if idx > 0:
                tracker.record_fallback_attempt()

            cves = self._retrieve_cves(candidate, tracker)
            if cves is None:
                # Provider failure — skip this candidate
                continue
            if not cves:
                # No CVEs for this CPE — try next candidate
                continue

            tracker.record_cves_retrieved(len(cves))

            # Process each CVE through version matching
            for cve_data in cves:
                finding = self._evaluate_cve(
                    cve_data, candidate, result, tracker
                )
                if finding is not None:
                    findings.append(finding)

            # If we found results from this candidate, don't fall back further
            if findings:
                break

        return findings

    def _build_candidate_order(
        self, result: CorrelationResult
    ) -> List[CPECandidate]:
        """Order candidates: selected first, then remaining sorted by confidence."""
        candidates: List[CPECandidate] = []
        seen_templates = set()

        if result.selected_candidate:
            candidates.append(result.selected_candidate)
            seen_templates.add(result.selected_candidate.cpe_template)

        # Add remaining candidates sorted by descending confidence
        remaining = sorted(
            [c for c in result.candidates if c.cpe_template not in seen_templates],
            key=lambda c: c.confidence,
            reverse=True,
        )
        candidates.extend(remaining)
        return candidates

    def _retrieve_cves(
        self,
        candidate: CPECandidate,
        tracker: NVDStatisticsTracker,
    ) -> Optional[List[Dict[str, Any]]]:
        """Retrieve CVEs for a candidate, checking cache first."""
        # Prefer exact version CPE if available, falling back to template
        cpe_query = candidate.resolved_cpe or candidate.cpe_template
        if not cpe_query and candidate.vendor and candidate.product:
            ver = candidate.detected_version or "*"
            cpe_query = f"cpe:2.3:a:{candidate.vendor}:{candidate.product}:{ver}:*:*:*:*:*:*:*" 

        cached = self.cache.get(cpe_query, candidate.detected_version)
        if cached is not None:
            tracker.record_cache_hit()
            return cached

        cves = self.provider.fetch_cves_by_cpe(cpe_query)
        if cves is not None:
            self.cache.put(cpe_query, cves, candidate.detected_version)

        return cves

    def _evaluate_cve(
        self,
        cve_data: Dict[str, Any],
        candidate: CPECandidate,
        result: CorrelationResult,
        tracker: NVDStatisticsTracker,
    ) -> Optional[CorrelatedVulnerability]:
        """Evaluate a single CVE against the detected version."""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Run version matching
        match_type, match_confidence = self.matcher.match_version(
            candidate.detected_version,
            cve_data,
            candidate.vendor,
            candidate.product,
        )

        # Version mismatch — skip
        if match_type == VersionMatchType.PARTIAL and match_confidence == 0:
            tracker.record_version_mismatch()
            return None

        tracker.record_version_match()

        # Calculate final confidence:
        #   weighted = 50% candidate confidence + 50% version match confidence
        final_confidence = int(
            (candidate.confidence * 0.5) + (match_confidence * 0.5)
        )

        if final_confidence < _MINIMUM_CONFIDENCE_THRESHOLD:
            tracker.record_below_threshold()
            return None

        tracker.record_correlated_vulnerability()

        # Extract enrichment data from CVE record
        cvss_score, severity = self._extract_cvss(cve_data)
        description = self._extract_description(cve_data)
        published = self._extract_published_date(cve_data)
        matched_cpe = self._extract_matched_cpe(cve_data, candidate)
        cwe = self._extract_cwe(cve_data)

        return CorrelatedVulnerability(
            cve_id=cve_id,
            technology_name=result.technology,
            source_cpe=candidate.cpe_template,
            matched_cpe=matched_cpe,
            correlation_source=f"cpe:2.3:a:{candidate.vendor}:{candidate.product}",
            matched_version=candidate.detected_version,
            version_match_type=match_type,
            confidence=final_confidence,
            candidate_confidence=candidate.confidence,
            cvss_v3_score=cvss_score,
            severity=severity,
            description=description,
            published_date=published,
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            cwe=cwe,
        )

    # ── Enrichment extractors (pure data extraction, no decisions) ─────────

    @staticmethod
    def _extract_cwe(cve_data: Dict[str, Any]) -> Optional[str]:
        """Extract CWE identifier from NVD weaknesses."""
        for w in cve_data.get("weaknesses", []):
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    return desc.get("value")
        return None

    @staticmethod
    def _extract_cvss(cve_data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        """Extract CVSS v3 base score and severity from NVD metrics."""
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
                if score is not None:
                    return float(score), severity
        return None, None

    @staticmethod
    def _extract_description(cve_data: Dict[str, Any]) -> Optional[str]:
        """Extract English description from NVD."""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value")
        return None

    @staticmethod
    def _extract_published_date(cve_data: Dict[str, Any]) -> Optional[datetime]:
        """Parse the published date from NVD ISO format."""
        raw = cve_data.get("published")
        if raw:
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        return None

    @staticmethod
    def _extract_matched_cpe(
        cve_data: Dict[str, Any], candidate: CPECandidate
    ) -> Optional[str]:
        """Find the exact CPE criteria string that matched from NVD configurations."""
        vendor = candidate.vendor.lower()
        product = candidate.product.lower()

        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 6:
                        if parts[3].lower() == vendor and parts[4].lower() == product:
                            return criteria
        return None

    def close(self) -> None:
        """Release resources."""
        self.provider.close()
