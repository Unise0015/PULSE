from typing import List

from pulse.enrichment.threat_intel.models import ThreatIntelRecord, ThreatIntelMatchType
from pulse.vulnerability.threat_mapping import ThreatMapper


class AttackEnricher:
    """Enriches threat intelligence records with MITRE ATT&CK mappings based on CWE."""

    def __init__(self):
        self.mapper = ThreatMapper()

    def enrich_batch(self, records: List[ThreatIntelRecord]) -> None:
        """Batch enriches multiple records with ATT&CK metadata in-place."""
        if not self.mapper.mapping:
            return

        for record in records:
            cwe = record.vulnerability.cwe
            if not cwe:
                continue

            cwe_id = cwe.strip().upper()
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"

            techniques_data = self.mapper.mapping.get(cwe_id)
            if techniques_data:
                record.attack_match_type = ThreatIntelMatchType.DIRECT
                record.enrichment_sources.append("ATT&CK")
                
                # Assume a base confidence of 90 for direct CWE mapping
                record.attack_confidence = 90

                for tech in techniques_data:
                    tech_id = tech.get("technique_id")
                    tactic = tech.get("tactic")

                    if tech_id and tech_id not in record.attack_techniques:
                        record.attack_techniques.append(tech_id)
                    if tactic and tactic not in record.attack_tactics:
                        record.attack_tactics.append(tactic)
