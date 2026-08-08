from typing import List, Dict

from pulse.enrichment.threat_intel.models import ThreatIntelRecord
from pulse.vulnerability.threat_intel import KEVProvider


class KEVAdapter:
    """Adapter to fetch KEV catalog independent of legacy findings."""

    def __init__(self):
        self.provider = KEVProvider()

    def get_catalog(self) -> Dict[str, dict]:
        """Returns mapping of CVE ID to KEV metadata."""
        return self.provider.get_catalog()


class KEVEnricher:
    """Enriches threat intelligence records with CISA KEV presence."""

    def __init__(self):
        self.adapter = KEVAdapter()

    def enrich_batch(self, records: List[ThreatIntelRecord]) -> None:
        """Batch enriches multiple records with KEV metadata in-place."""
        catalog = self.adapter.get_catalog()
        if not catalog:
            return

        for record in records:
            cve_id = record.vulnerability.cve_id
            if cve_id in catalog:
                record.kev_listed = True
                record.enrichment_sources.append("KEV")
