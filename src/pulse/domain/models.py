from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pulse.domain.version import BranchStatus, RegistryType, NormalizedAffectedRange
class PluginExecutionStatus(Enum):
    SUCCESS = "Success"
    WARNING = "Warning"
    FAILED = "Failed"
    SKIPPED = "Skipped"

@dataclass
class PluginDiagnostics:
    status: PluginExecutionStatus
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_ms: int = 0

@dataclass
class ReportArtifact:
    id: Optional[int]
    scan_id: str
    format: str
    path: str
    created_at: datetime = field(default_factory=datetime.now)
    file_size: Optional[int] = 0
    sha256: Optional[str] = None
    status: str = "AVAILABLE"


@dataclass
class SecurityFixRecommendation:
    minimum_safe_version: Optional[str] = None
    latest_security_fix: Optional[str] = None
    latest_stable_version: Optional[str] = None
    rationale: str = ""

@dataclass
class VersionMetadata:
    current_version: str
    latest_stable_version: Optional[str]
    latest_security_fix: Optional[str]    # Latest patch in current branch
    minimum_safe_version: Optional[str]   # Lowest safe version overall >= current
    latest_lts_version: Optional[str]
    canonical_name: str
    display_name: str
    source_registry: RegistryType
    source_confidence: str                 # "authoritative" | "cached" | "offline" | "estimated"
    registry_available: bool               # True if registry responded, False if timed out / cached fallback
    verification_state: str                # "VERIFIED" | "UNVERIFIED" | "UNKNOWN" | "STALE"
    branch_status: BranchStatus
    source_timestamp: datetime
    recommendation: Optional[SecurityFixRecommendation] = None

@dataclass
class AttackTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str

    @property
    def id(self) -> str:
        return self.technique_id

    @property
    def display_name(self) -> str:
        if self.technique_name and self.technique_name.strip() and self.technique_name.strip().lower() not in ("none", "unknown"):
            return f"{self.technique_id} — {self.technique_name.strip()}"
        return self.technique_id

@dataclass
class PackageInfo:
    name: str
    version: str
    ecosystem: str
    dependency_type: str = "DIRECT"  # DIRECT or TRANSITIVE
    reachability: str = "UNKNOWN"
    latest_version: Optional[str] = None
    latest_release_date: Optional[str] = None
    homepage: Optional[str] = None
    version_metadata: Optional[VersionMetadata] = None
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExploitIntelligence:
    public_poc: bool = False
    poc_source: Optional[str] = None
    exploit_maturity: str = "Unknown"
    exploit_references: List[str] = field(default_factory=list)

class FindingSourceType(str, Enum):
    PACKAGE = "package"
    WEBSITE = "website"
    DOCKER = "docker"


@dataclass
class VulnerabilityFinding:
    package: PackageInfo
    cve_id: str
    cvss_score: float = 0.0
    cvss_severity: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    epss_score: float = 0.0
    epss_percent: str = "0%"
    kev_match: bool = False
    risk_heat_score: int = 0
    description: str = ""
    fix_version: Optional[str] = None
    source: str = "OSV"
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    nvd_url: str = ""
    kev_date_added: Optional[str] = None
    summary: Optional[str] = None          # 250-char truncated description
    reference_url: Optional[str] = None    # Primary advisory URL
    cwe: Optional[str] = None
    cvss_vector: Optional[str] = None
    attack_techniques: List[AttackTechnique] = field(default_factory=list)
    exploit_intelligence: Optional[ExploitIntelligence] = None
    affected_ranges: List[NormalizedAffectedRange] = field(default_factory=list)
    source_type: FindingSourceType = FindingSourceType.PACKAGE
    source_asset: Optional[str] = None
    detection_confidence: int = 0
    source_evidence: List[str] = field(default_factory=list)

    @property
    def cwe_id(self) -> Optional[str]:
        return self.cwe

    @property
    def cwe_name(self) -> Optional[str]:
        return getattr(self, "_cwe_name", None)

    def normalize_severity(self) -> None:
        sev = self.cvss_severity.upper() if self.cvss_severity else ""
        if not sev or sev in ("UNKNOWN", "NONE"):
            score = self.cvss_score
            if score >= 9.0:
                self.cvss_severity = "CRITICAL"
            elif score >= 7.0:
                self.cvss_severity = "HIGH"
            elif score >= 4.0:
                self.cvss_severity = "MEDIUM"
            elif score >= 0.1:
                self.cvss_severity = "LOW"
            else:
                if self.kev_match or self.epss_score >= 1.0:
                    self.cvss_severity = "LOW"
                else:
                    self.cvss_severity = "INFORMATIONAL"
        elif sev == "INFORMATIONAL":
            if self.kev_match or self.epss_score >= 1.0 or self.cvss_score > 0.0:
                self.cvss_severity = "LOW"


@dataclass
class AttackPath:
    package_name: str
    package_version: str
    cve_id: str
    cwe: Optional[str]
    attack_techniques: List[AttackTechnique]
    attack_tactics: List[str]
    cvss_score: float
    epss_score: float
    kev_match: bool
    risk_score: int
    exposure_score: int
    exploit_maturity: str = "Unknown"
    source_type: FindingSourceType = FindingSourceType.PACKAGE



@dataclass
class DependencyNode:
    """A node in the dependency graph representing a single package."""
    package_name: str
    version: str
    ecosystem: str
    direct: bool
    vulnerable: bool
    cve_count: int = 0
    depth: int = 0
    children: List["DependencyNode"] = field(default_factory=list)


@dataclass
class SupplyChainMetrics:
    """Aggregated supply chain exposure metrics for a scan."""
    direct_count: int = 0
    transitive_count: int = 0
    vulnerable_direct: int = 0
    vulnerable_transitive: int = 0
    max_depth: int = 0
    critical_chains: int = 0

class DetectionStatus(str, Enum):
    VERIFIED = "Verified"
    ESTIMATED = "Estimated"
    UNKNOWN = "Unknown"

class TechnologyCategory(str, Enum):
    FRAMEWORK = "Framework"
    CMS = "CMS"
    SERVER = "Web Server"
    CDN = "CDN"
    RUNTIME = "Runtime"
    ANALYTICS = "Analytics"
    SECURITY = "Security"
    DATABASE = "Database"
    BUILD_TOOL = "Build Tool"
    UI_LIBRARY = "Frontend Library"
    WAF = "WAF"
    PROXY = "PROXY"
    SEARCH_ENGINE = "SEARCH_ENGINE"
    MONITORING = "MONITORING"
    MESSAGING = "MESSAGING"

class DetectionMethod(str, Enum):
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    HTML = "HTML"
    SCRIPT = "SCRIPT"
    META = "META"
    URL_PATTERN = "URL_PATTERN"

class ConfidenceBand(str, Enum):
    LOW = "LOW"          # 0-39
    MEDIUM = "MEDIUM"    # 40-69
    HIGH = "HIGH"        # 70-94
    VERIFIED = "VERIFIED"# 95-100

class EvidenceReliability(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED = "VERIFIED"

class DetectionMode(str, Enum):
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"

@dataclass
class CPECandidate:
    cpe: str
    confidence: int

@dataclass
class DetectionEvidence:
    method: DetectionMethod
    source: str
    value: str
    confidence: int
    description: str
    reliability: EvidenceReliability = EvidenceReliability.MEDIUM

@dataclass
class SignatureExecutionMetrics:
    signature_id: str
    execution_time_ms: float
    evidence_generated: int
    technologies_detected: int
    match_rate: float = 0.0

@dataclass
class FingerprintStatistics:
    signatures_loaded: int
    signatures_matched: int
    evidence_items: int
    technologies_detected: int
    execution_metrics: List[SignatureExecutionMetrics] = field(default_factory=list)

@dataclass
class TechnologyFingerprint:
    name: str
    version: Optional[str]
    category: TechnologyCategory
    confidence: int = 0
    confidence_band: ConfidenceBand = ConfidenceBand.LOW
    evidence_count: int = 0
    raw_match_count: int = 0
    version_status: DetectionStatus = DetectionStatus.UNKNOWN
    evidence: List[DetectionEvidence] = field(default_factory=list)
    version_evidence: Optional[DetectionEvidence] = None
    version_confidence: int = 0  # 100=header, 90=meta, 80=script, 50=inferred, 0=unknown
    signature_id: str = ""
    signature_version: str = "1.0"
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)
    cpe_candidates: List[CPECandidate] = field(default_factory=list)
    ecosystem: Optional[str] = None
    correlation_supported: bool = False
    detection_mode: DetectionMode = DetectionMode.PASSIVE
    vendor: Optional[str] = None
    domain: str = "web"
    direct_detection: bool = True
    inferred: bool = False
    vulnerability_status: str = "UNTESTED"
    
    # Backward-compatible parameters mapped in __post_init__
    confidence_score: Optional[int] = None
    detection_source: Optional[str] = None

    
    def __post_init__(self) -> None:
        if isinstance(self.category, str):
            for cat in TechnologyCategory:
                if cat.value.lower() == self.category.lower() or cat.name.lower() == self.category.lower():
                    self.category = cat
                    break
        if isinstance(self.version_status, str):
            for stat in DetectionStatus:
                if stat.value.lower() == self.version_status.lower() or stat.name.lower() == self.version_status.lower():
                    self.version_status = stat
                    break
                    
        # Backward-compatibility fallback
        if self.confidence == 0 and self.confidence_score is not None:
            self.confidence = self.confidence_score
        elif self.confidence_score is None:
            self.confidence_score = self.confidence

        if self.detection_source is None:
            methods = sorted(list(set(ev.method.value for ev in self.evidence)))
            self.detection_source = ", ".join(methods) if methods else "UNKNOWN"

        if self.confidence >= 95:
            self.confidence_band = ConfidenceBand.VERIFIED
        elif self.confidence >= 70:
            self.confidence_band = ConfidenceBand.HIGH
        elif self.confidence >= 40:
            self.confidence_band = ConfidenceBand.MEDIUM
        else:
            self.confidence_band = ConfidenceBand.LOW

@dataclass
class SecurityHeaderStatus:
    header_name: str
    status: str  # Present, Missing, Misconfigured
    details: str

class CorrelationStatus(str, Enum):
    NOT_RUN = "Not Run"
    RUNNING = "Running"
    COMPLETED = "Completed"
    PARTIAL = "Partial"
    FAILED = "Failed"

@dataclass
class WebsiteAssessment:
    url: str
    technologies: List[TechnologyFingerprint] = field(default_factory=list)
    security_headers: List[SecurityHeaderStatus] = field(default_factory=list)
    statistics: Optional[FingerprintStatistics] = None
    correlation_status: CorrelationStatus = CorrelationStatus.NOT_RUN
    correlation_completed_at: Optional[datetime] = None
    correlated_technologies: int = 0
    failed_technologies: int = 0
    technology_eligibilities: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    timestamp: datetime
    hostname: str
    tool_version: str
    packages_scanned: int
    attack_surface_score: int
    scan_duration_seconds: float = 0.0
    target_type: str = "global"
    target_id: str = "global"
    target_fingerprint: str = ""
    
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    attack_paths: List['AttackPath'] = field(default_factory=list)
    dependency_trees: List['DependencyNode'] = field(default_factory=list)
    supply_chain_metrics: Optional['SupplyChainMetrics'] = None
    website_assessment: Optional['WebsiteAssessment'] = None
    detected_ecosystems: List[str] = field(default_factory=list)
    plugin_diagnostics: Dict[str, PluginDiagnostics] = field(default_factory=dict)
    upgrade_recommendations: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def make_package_key(ecosystem: str, package_name: str) -> str:
        eco = (ecosystem or "unknown").lower().strip()
        pkg = (package_name or "unknown").lower().strip()
        return f"{eco}:{pkg}"

    def get_recommendation(self, package_name: str, ecosystem: Optional[str] = None) -> Optional[Any]:
        if ecosystem:
            key = self.make_package_key(ecosystem, package_name)
            if key in self.upgrade_recommendations:
                return self.upgrade_recommendations[key]
        pkg_lower = package_name.lower().strip()
        for k, rec in self.upgrade_recommendations.items():
            if k == pkg_lower or k.endswith(f":{pkg_lower}"):
                return rec
        return None
    
    @property
    def vulnerable_packages_count(self) -> int:
        # A single package might have multiple CVEs, count unique packages
        unique_pkgs = { (f.package.name, f.package.version) for f in self.findings }
        return len(unique_pkgs)
        
    @property
    def clean_packages_count(self) -> int:
        return self.packages_scanned - self.vulnerable_packages_count
        
    @property
    def critical_count(self) -> int:
        return self.severity_counts.get("CRITICAL", 0)
        
    @property
    def high_count(self) -> int:
        return self.severity_counts.get("HIGH", 0)
        
    @property
    def medium_count(self) -> int:
        return self.severity_counts.get("MEDIUM", 0)
        
    @property
    def low_count(self) -> int:
        return self.severity_counts.get("LOW", 0)

    @property
    def informational_count(self) -> int:
        return self.severity_counts.get("INFORMATIONAL", 0)

    @property
    def severity_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for finding in self.findings:
            finding.normalize_severity()
            sev = finding.cvss_severity.upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["INFORMATIONAL"] += 1
        return counts

    @property
    def kev_matches_count(self) -> int:
        return sum(1 for f in self.findings if f.kev_match)

    @property
    def kev_matches(self) -> int:
        return self.kev_matches_count
        
    @property
    def average_risk_score(self) -> int:
        if not self.findings:
            return 0
        return sum(f.risk_heat_score for f in self.findings) // len(self.findings)
        
    @property
    def highest_risk_score(self) -> int:
        if not self.findings:
            return 0
        return max(f.risk_heat_score for f in self.findings)

@dataclass
class PostureDelta:
    """Represents security posture metrics delta between two consecutive scans."""
    previous_score: int = 0
    current_score: int = 0
    
    new_cves: List[VulnerabilityFinding] = field(default_factory=list)
    remediated_cves: List[str] = field(default_factory=list) # CVE IDs
    
    risk_score_change: int = 0
    kev_change_count: int = 0
    critical_count_change: int = 0
    
    highest_new_risk: Optional[VulnerabilityFinding] = None
    highest_resolved_risk_score: Optional[int] = None
    highest_resolved_cve: Optional[str] = None


@dataclass
class DependencyEdge:
    parent_name: str
    child_name: str


def deduplicate_and_merge_findings(findings: List[Any]) -> List[Any]:
    """Deduplicates findings using stable identity (package_name, package_version, cve_id) while preserving merged enrichment."""
    if not findings:
        return []

    if not any(hasattr(f, "package") and hasattr(f, "cve_id") for f in findings):
        return findings

    merged_map: Dict[tuple, Any] = {}
    non_findings: List[Any] = []

    for f in findings:
        if not hasattr(f, "package") or not hasattr(f, "cve_id"):
            non_findings.append(f)
            continue

        pkg_name = f.package.name.lower() if f.package and getattr(f.package, "name", None) else "unknown"
        pkg_ver = f.package.version if f.package and getattr(f.package, "version", None) else "unknown"
        cve_id = f.cve_id.upper() if f.cve_id else "NO-CVE"

        key = (pkg_name, pkg_ver, cve_id)

        if key not in merged_map:
            merged_map[key] = f
        else:
            existing = merged_map[key]
            existing.cvss_score = max(existing.cvss_score, f.cvss_score)
            if existing.cvss_severity in ("UNKNOWN", "NONE") and f.cvss_severity not in ("UNKNOWN", "NONE"):
                existing.cvss_severity = f.cvss_severity
            existing.epss_score = max(existing.epss_score, f.epss_score)
            if f.epss_percent and f.epss_percent != "0%":
                existing.epss_percent = f.epss_percent
            existing.kev_match = existing.kev_match or f.kev_match
            existing.risk_heat_score = max(existing.risk_heat_score, f.risk_heat_score)
            
            if f.cwe and not existing.cwe:
                existing.cwe = f.cwe
            if f.cvss_vector and not existing.cvss_vector:
                existing.cvss_vector = f.cvss_vector
            if f.nvd_url and not existing.nvd_url:
                existing.nvd_url = f.nvd_url
            if f.description and len(f.description) > len(existing.description or ""):
                existing.description = f.description
                existing.summary = f.summary or f.description[:250]

            if f.exploit_intelligence:
                if not existing.exploit_intelligence:
                    existing.exploit_intelligence = f.exploit_intelligence
                else:
                    existing.exploit_intelligence.public_poc = existing.exploit_intelligence.public_poc or f.exploit_intelligence.public_poc
                    if f.exploit_intelligence.poc_source and not existing.exploit_intelligence.poc_source:
                        existing.exploit_intelligence.poc_source = f.exploit_intelligence.poc_source
                    if f.exploit_intelligence.exploit_maturity not in ("Unknown", "No Public PoC Identified"):
                        existing.exploit_intelligence.exploit_maturity = f.exploit_intelligence.exploit_maturity

            if f.attack_techniques:
                existing_tech_ids = {t.id for t in existing.attack_techniques}
                for tech in f.attack_techniques:
                    if tech.id not in existing_tech_ids:
                        existing.attack_techniques.append(tech)
                        existing_tech_ids.add(tech.id)

    return list(merged_map.values()) + non_findings

