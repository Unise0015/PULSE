from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

class CorrelationTargetType(Enum):
    PACKAGE = "package"
    WEBSITE = "website"
    CONTAINER = "container"
    SBOM = "sbom"

class ResolverMatchType(Enum):
    EXACT = "EXACT"
    ALIAS = "ALIAS"
    HEURISTIC = "HEURISTIC"
    FALLBACK = "FALLBACK"

@dataclass
class CPECandidate:
    cpe_template: str
    detected_version: Optional[str]
    resolved_cpe: Optional[str]
    confidence: int
    source: str
    vendor: str
    product: str
    exact_version_match: bool
    match_type: ResolverMatchType

@dataclass
class CorrelationTarget:
    target_type: CorrelationTargetType
    name: str
    version: Optional[str]
    ecosystem: Optional[str] = None
    cpe_string: Optional[str] = None

@dataclass
class CorrelationResult:
    technology: str
    inventory_technology_key: str
    candidates: List[CPECandidate]
    selected_candidate: Optional[CPECandidate]
    resolution_confidence: int

@dataclass
class CorrelationStatistics:
    technologies_processed: int
    candidates_generated: int
    successful_resolutions: int
    unresolved_technologies: int

# CorrelatedVulnerability has been promoted to pulse.enrichment.nvd.models (M10.2.4)
