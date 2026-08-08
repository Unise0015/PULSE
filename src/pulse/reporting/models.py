from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict, Any

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def from_str(cls, val: str) -> "Severity":
        val_upper = (val or "").upper()
        for sev in cls:
            if sev.value == val_upper:
                return sev
        return cls.INFORMATIONAL

@dataclass
class ExecutiveSummaryModel:
    target_id: str
    target_type: str
    scan_started: datetime
    scan_finished: datetime
    duration: timedelta
    packages_scanned: int
    vulnerable_count: int
    attack_surface_score: int

@dataclass
class RiskSummaryModel:
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    kev_matches_count: int
    average_risk_score: int
    direct_packages_count: int
    transitive_packages_count: int
    previous_score: Optional[int] = None
    score_delta: Optional[int] = None

@dataclass
class ReportFindingModel:
    cve_id: str
    package_name: str
    package_version: str
    ecosystem: str
    severity: Severity
    cvss_score: float
    epss_percent: str
    kev_match: bool
    risk_heat_score: int
    description: str
    fix_version: Optional[str] = None
    remediation_command: Optional[str] = None
    attack_techniques: List[Any] = field(default_factory=list)
    nvd_url: Optional[str] = None

@dataclass
class WebsiteTechnologyModel:
    name: str
    version: Optional[str]
    category: str
    confidence: int
    correlated: bool
    vulnerability_count: int

@dataclass
class PackageInventoryItem:
    name: str
    version: str
    ecosystem: str
    direct: bool
    vulnerable: bool

@dataclass
class RemediationItem:
    title: str
    command: str
    priority: int
    affected_packages: List[str]

@dataclass
class BaseSection:
    name: str

@dataclass
class WebsiteAssessmentSection(BaseSection):
    url: str
    correlation_status: str
    technologies: List[WebsiteTechnologyModel] = field(default_factory=list)

@dataclass
class DependencyInventorySection(BaseSection):
    total_packages: int
    items: List[PackageInventoryItem] = field(default_factory=list)

@dataclass
class RemediationSection(BaseSection):
    items: List[RemediationItem] = field(default_factory=list)

@dataclass
class ReportMetadata:
    pulse_version: str
    report_schema_version: str = "2.0"
    template_version: str = "1.0"
    generated_at: datetime = field(default_factory=datetime.now)
    database_versions: Dict[str, str] = field(default_factory=dict)

@dataclass
class ReportModel:
    executive_summary: ExecutiveSummaryModel
    risk_summary: RiskSummaryModel
    findings: List[ReportFindingModel]
    sections: List[BaseSection] = field(default_factory=list)
    metadata: ReportMetadata = field(default_factory=lambda: ReportMetadata(pulse_version="4.0.0"))
