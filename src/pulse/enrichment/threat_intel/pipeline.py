import logging
from typing import List, Tuple

from pulse.enrichment.nvd.models import CorrelatedVulnerability
from pulse.enrichment.threat_intel.models import ThreatIntelRecord
from pulse.enrichment.threat_intel.statistics import ThreatIntelStatistics
from pulse.enrichment.threat_intel.epss import EPSSEnricher
from pulse.enrichment.threat_intel.kev import KEVEnricher
from pulse.enrichment.threat_intel.attack import AttackEnricher
from pulse.enrichment.threat_intel.exploit import ExploitEnricher
from pulse.enrichment.threat_intel.cache import ThreatIntelCache

logger = logging.getLogger(__name__)


class ThreatIntelligencePipeline:
    """Orchestrates the enrichment of CorrelatedVulnerabilities.
    
    Responsibilities:
      - Coordinate EPSS, KEV, ATT&CK, and Exploit enrichment.
      - Calculate enrichment_confidence based on data retrieval.
      - Aggregate ThreatIntelStatistics.
      - Cache fully enriched ThreatIntelRecords.
      
    This pipeline MUST NOT calculate risk scores.
    """

    def __init__(self, cache_ttl_hours: int = 24):
        self.cache = ThreatIntelCache(ttl_hours=cache_ttl_hours)
        self.epss = EPSSEnricher()
        self.kev = KEVEnricher()
        self.attack = AttackEnricher()
        self.exploit = ExploitEnricher()

    def enrich(
        self, vulnerabilities: List[CorrelatedVulnerability]
    ) -> Tuple[List[ThreatIntelRecord], ThreatIntelStatistics]:
        stats = ThreatIntelStatistics()
        records: List[ThreatIntelRecord] = []
        
        # We process in batches, but handle cache at the individual level.
        # Uncached records will be grouped, sent to the enrichers, and then cached.
        uncached_records: List[ThreatIntelRecord] = []

        for vuln in vulnerabilities:
            stats.vulnerabilities_processed += 1
            if not vuln.cve_id:
                continue

            cached_data = self.cache.get(vuln.cve_id)
            if cached_data is not None:
                stats.cache_hits += 1
                record = self._deserialize_record(vuln, cached_data)
                records.append(record)
                self._update_stats_from_record(record, stats)
            else:
                record = ThreatIntelRecord(vulnerability=vuln)
                uncached_records.append(record)
                records.append(record)

        if uncached_records:
            self._enrich_batch(uncached_records, stats)
            for record in uncached_records:
                self.cache.put(record.vulnerability.cve_id, self._serialize_record(record))
                self._update_stats_from_record(record, stats)

        return records, stats

    def _enrich_batch(self, records: List[ThreatIntelRecord], stats: ThreatIntelStatistics) -> None:
        """Run all enrichers on a batch of uncached records."""
        try:
            self.epss.enrich_batch(records)
        except Exception as e:
            logger.warning("EPSS enrichment failed: %s", e)
            stats.enrichment_failures += 1

        try:
            self.kev.enrich_batch(records)
        except Exception as e:
            logger.warning("KEV enrichment failed: %s", e)
            stats.enrichment_failures += 1

        try:
            self.attack.enrich_batch(records)
        except Exception as e:
            logger.warning("ATT&CK enrichment failed: %s", e)
            stats.enrichment_failures += 1

        try:
            self.exploit.enrich_batch(records)
        except Exception as e:
            logger.warning("Exploit enrichment failed: %s", e)
            stats.enrichment_failures += 1

        # Calculate enrichment confidence
        for record in records:
            confidence = 0
            if record.epss_score is not None:
                confidence += 40
            if record.kev_listed:
                confidence += 20
            if record.attack_techniques:
                confidence += 40
                
            record.enrichment_confidence = confidence

    def _update_stats_from_record(self, record: ThreatIntelRecord, stats: ThreatIntelStatistics) -> None:
        """Update summary stats from a fully enriched record."""
        if record.epss_score is not None:
            stats.epss_matches += 1
        if record.kev_listed:
            stats.kev_matches += 1
        if record.attack_techniques:
            stats.attack_matches += 1
        if record.exploit_available:
            stats.exploit_matches += 1
            
        if not record.enrichment_sources:
            stats.unenriched_vulnerabilities += 1

    def _serialize_record(self, record: ThreatIntelRecord) -> dict:
        """Convert enrichment data to a dictionary for caching."""
        return {
            "epss_score": record.epss_score,
            "epss_percentile": record.epss_percentile,
            "kev_listed": record.kev_listed,
            "attack_techniques": record.attack_techniques,
            "attack_tactics": record.attack_tactics,
            "attack_confidence": record.attack_confidence,
            "attack_match_type": record.attack_match_type.value if record.attack_match_type else None,
            "exploit_available": record.exploit_available,
            "exploit_match_type": record.exploit_match_type.value if record.exploit_match_type else None,
            "enrichment_confidence": record.enrichment_confidence,
            "enrichment_sources": record.enrichment_sources,
        }

    def _deserialize_record(self, vuln: CorrelatedVulnerability, data: dict) -> ThreatIntelRecord:
        """Reconstruct a ThreatIntelRecord from cached enrichment data."""
        from pulse.enrichment.threat_intel.models import ThreatIntelMatchType
        
        record = ThreatIntelRecord(vulnerability=vuln)
        record.epss_score = data.get("epss_score")
        record.epss_percentile = data.get("epss_percentile")
        record.kev_listed = data.get("kev_listed", False)
        record.attack_techniques = data.get("attack_techniques", [])
        record.attack_tactics = data.get("attack_tactics", [])
        record.attack_confidence = data.get("attack_confidence", 0)
        
        amt = data.get("attack_match_type")
        if amt:
            record.attack_match_type = ThreatIntelMatchType(amt)
            
        record.exploit_available = data.get("exploit_available", False)
        
        emt = data.get("exploit_match_type")
        if emt:
            record.exploit_match_type = ThreatIntelMatchType(emt)
            
        record.enrichment_confidence = data.get("enrichment_confidence", 0)
        record.enrichment_sources = data.get("enrichment_sources", [])
        return record
