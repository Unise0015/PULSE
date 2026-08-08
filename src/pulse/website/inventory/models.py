from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from pulse.domain.models import TechnologyCategory, DetectionStatus, ConfidenceBand

@dataclass
class InventoryTechnology:
    technology_key: str
    name: str
    category: TechnologyCategory
    version: Optional[str]
    version_status: DetectionStatus
    confidence: int
    confidence_band: ConfidenceBand
    fingerprint_hash: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    evidence_count: int
    source_signature: str
    cpe_candidates: List[str] = field(default_factory=list)
    source_fingerprints: List[str] = field(default_factory=list)
    risk_score: int = 0
    inventory_version: str = "1.0"
