from dataclasses import dataclass


@dataclass
class ThreatIntelStatistics:
    vulnerabilities_processed: int = 0
    epss_matches: int = 0
    kev_matches: int = 0
    attack_matches: int = 0
    exploit_matches: int = 0
    cache_hits: int = 0
    enrichment_failures: int = 0
    unenriched_vulnerabilities: int = 0
