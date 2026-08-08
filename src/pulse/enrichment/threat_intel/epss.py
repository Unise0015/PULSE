from typing import List, Dict, Optional

from pulse.enrichment.threat_intel.models import ThreatIntelRecord
from pulse.vulnerability.threat_intel import EPSSProvider


class EPSSAdapter:
    """Adapter to fetch EPSS scores via CVE IDs rather than legacy findings."""
    
    def __init__(self):
        self.provider = EPSSProvider()

    def get_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """Returns mapping of CVE ID -> {'score': float, 'percent': str}."""
        return self.provider.get_scores(cve_ids)


class EPSSEnricher:
    """Enriches threat intelligence records with EPSS data."""

    def __init__(self):
        self.adapter = EPSSAdapter()

    def enrich_batch(self, records: List[ThreatIntelRecord]) -> None:
        """Batch enriches multiple records with EPSS scores in-place."""
        cve_ids = [r.vulnerability.cve_id for r in records if r.vulnerability.cve_id]
        if not cve_ids:
            return

        scores = self.adapter.get_scores(cve_ids)

        for record in records:
            cve_id = record.vulnerability.cve_id
            if cve_id in scores:
                record.epss_score = scores[cve_id].get("score")
                
                # Parse "99.7%" string back to float for the model
                percent_str = scores[cve_id].get("percent", "0.0%")
                try:
                    record.epss_percentile = float(percent_str.strip("%"))
                except (ValueError, AttributeError):
                    record.epss_percentile = 0.0

                record.enrichment_sources.append("EPSS")
