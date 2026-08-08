from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from pulse.domain.models import ScanResult, PostureDelta
from pulse.security_advisor import SecurityAdvisor

@dataclass
class ReportContext:
    """Immutable context provided to ReportBuilder to construct a ReportModel."""
    scan_result: ScanResult
    scan_id: str
    generated_at: datetime = field(default_factory=datetime.now)
    posture_delta: Optional[PostureDelta] = None
    advisor: Optional[SecurityAdvisor] = None
    options: Dict[str, Any] = field(default_factory=dict)
