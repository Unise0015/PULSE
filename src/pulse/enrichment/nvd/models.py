from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any


class VersionMatchType(Enum):
    EXACT = "EXACT"
    RANGE = "RANGE"
    PARTIAL = "PARTIAL"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"


@dataclass
class CorrelatedVulnerability:
    """A vulnerability correlated from NVD via CPE matching.
    
    Preserves full provenance chain for auditability:
        CPE Candidate → NVD Query → Version Match → Finding
    """
    # --- Core identity ---
    cve_id: str
    technology_name: str

    # --- CPE provenance ---
    source_cpe: str                          # CPE template used for NVD query
    matched_cpe: Optional[str]               # Exact CPE criteria string that matched
    correlation_source: str                   # e.g. "cpe:2.3:a:vercel:next.js"

    # --- Version intelligence ---
    matched_version: Optional[str]
    version_match_type: VersionMatchType

    # --- Confidence ---
    confidence: int                           # Final correlation confidence
    candidate_confidence: int                 # Upstream CPE candidate confidence

    # --- NVD enrichment ---
    cvss_v3_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    nvd_url: Optional[str] = None
    cwe: Optional[str] = None

    # --- Raw provenance (for debugging/future UI) ---
    matched_configuration: Optional[Dict[str, Any]] = field(default=None, repr=False)


@dataclass
class NVDCorrelationStatistics:
    """Metrics from a single NVD correlation run."""
    cpes_processed: int = 0
    cves_retrieved: int = 0
    version_matches: int = 0
    version_mismatches: int = 0
    correlated_vulnerabilities: int = 0
    cache_hits: int = 0
    fallback_attempts: int = 0
    below_threshold_filtered: int = 0
