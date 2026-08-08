from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from pulse.enrichment.nvd.models import CorrelatedVulnerability


class ThreatIntelMatchType(Enum):
    DIRECT = "DIRECT"
    INFERRED = "INFERRED"
    HEURISTIC = "HEURISTIC"


@dataclass
class ThreatIntelRecord:
    """A vulnerability enriched with external threat intelligence signals."""
    vulnerability: CorrelatedVulnerability

    # EPSS signals
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    # KEV signals
    kev_listed: bool = False

    # ATT&CK signals
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    attack_confidence: int = 0
    attack_match_type: Optional[ThreatIntelMatchType] = None

    # Exploit signals
    exploit_available: bool = False
    exploit_match_type: Optional[ThreatIntelMatchType] = None

    # Overall enrichment
    enrichment_confidence: int = 0
    enrichment_sources: List[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    """Reserved contract for M10.2.6 Risk Scoring Engine.
    
    This establishes the strict boundary between enrichment (M10.2.5)
    and risk calculation (M10.2.6).
    """
    threat_record: ThreatIntelRecord
    risk_score: int
    risk_level: str
    reasons: List[str]
