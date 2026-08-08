from pulse.enrichment.nvd.models import NVDCorrelationStatistics


class NVDStatisticsTracker:
    """Accumulates correlation metrics during a single correlation run.
    
    Usage:
        tracker = NVDStatisticsTracker()
        tracker.record_cpe_processed()
        tracker.record_cache_hit()
        ...
        stats = tracker.finalize()
    """

    def __init__(self):
        self._stats = NVDCorrelationStatistics()

    def record_cpe_processed(self) -> None:
        self._stats.cpes_processed += 1

    def record_cves_retrieved(self, count: int) -> None:
        self._stats.cves_retrieved += count

    def record_version_match(self) -> None:
        self._stats.version_matches += 1

    def record_version_mismatch(self) -> None:
        self._stats.version_mismatches += 1

    def record_correlated_vulnerability(self) -> None:
        self._stats.correlated_vulnerabilities += 1

    def record_cache_hit(self) -> None:
        self._stats.cache_hits += 1

    def record_fallback_attempt(self) -> None:
        self._stats.fallback_attempts += 1

    def record_below_threshold(self) -> None:
        self._stats.below_threshold_filtered += 1

    def finalize(self) -> NVDCorrelationStatistics:
        """Return an immutable snapshot of the accumulated statistics."""
        return NVDCorrelationStatistics(
            cpes_processed=self._stats.cpes_processed,
            cves_retrieved=self._stats.cves_retrieved,
            version_matches=self._stats.version_matches,
            version_mismatches=self._stats.version_mismatches,
            correlated_vulnerabilities=self._stats.correlated_vulnerabilities,
            cache_hits=self._stats.cache_hits,
            fallback_attempts=self._stats.fallback_attempts,
            below_threshold_filtered=self._stats.below_threshold_filtered,
        )
