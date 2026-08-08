from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional

class RecommendationStrategy(str, Enum):
    MINIMUM_SAFE = "MINIMUM_SAFE"
    LATEST_STABLE = "LATEST_STABLE"
    LATEST_LTS = "LATEST_LTS"
    SECURITY_ONLY = "SECURITY_ONLY"
    CUSTOM = "CUSTOM"

class RecommendationMethod(str, Enum):
    VERIFIED_SCAN = "VERIFIED_SCAN"
    ADVISORY_CONFIRMED = "ADVISORY_CONFIRMED"
    REGISTRY_CONFIRMED = "REGISTRY_CONFIRMED"
    INFERRED = "INFERRED"

    def rank(self) -> int:
        hierarchy = {
            "VERIFIED_SCAN": 4,
            "ADVISORY_CONFIRMED": 3,
            "REGISTRY_CONFIRMED": 2,
            "INFERRED": 1
        }
        return hierarchy.get(self.value, 1)

class RecommendationConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class RecommendationEvidence:
    method: RecommendationMethod = RecommendationMethod.ADVISORY_CONFIRMED
    policy_version: str = "PULSE Risk Policy v4.0"
    providers_used: List[str] = field(default_factory=lambda: ["OSV", "NVD", "KEV", "EPSS"])
    verified_at: Optional[datetime] = None
    cache_hit: bool = False
    confidence: RecommendationConfidence = RecommendationConfidence.HIGH

    def upgrade_to(self, new_evidence: "RecommendationEvidence") -> None:
        """Upgrades evidence level without downgrading higher evidence methods."""
        if new_evidence.method.rank() > self.method.rank():
            self.method = new_evidence.method
            self.verified_at = new_evidence.verified_at or self.verified_at
            self.cache_hit = new_evidence.cache_hit
            self.confidence = new_evidence.confidence
            if new_evidence.providers_used:
                self.providers_used = new_evidence.providers_used

class MigrationRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class PackageManager(str, Enum):
    PIP = "pip"
    POETRY = "poetry"
    UV = "uv"
    NPM = "npm"
    PNPM = "pnpm"
    YARN = "yarn"
    CARGO = "cargo"
    COMPOSER = "composer"
    DOTNET = "dotnet"
    GEM = "gem"

@dataclass
class PackageManagerCommand:
    manager: PackageManager
    description: str
    command: str
    recommended: bool = False

@dataclass
class VerificationSource:
    source: str
    verified: bool
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class UpgradeRecommendation:
    """Strongly typed upgrade recommendation produced by Version Intelligence."""
    package_name: str
    ecosystem: str
    current_version: str
    status: str = "Supported" # EOL, Maintenance, Supported
    minimum_known_safe: Optional[str] = None
    latest_stable: Optional[str] = None
    recommended_version: Optional[str] = None
    recommendation_reason: str = "Patches all identified security vulnerabilities with minimum migration risk"
    strategy: RecommendationStrategy = RecommendationStrategy.MINIMUM_SAFE
    alternative_version: Optional[str] = None
    alternative_reason: str = "Latest stable release for long-term support"
    confidence: RecommendationConfidence = RecommendationConfidence.HIGH
    suitability_rating: str = "★★★★★ Production Ready"
    migration_risk: MigrationRisk = MigrationRisk.LOW
    verified_safe: bool = False
    verification_scan_performed: bool = False
    verification_findings: int = 0
    verification_blocking_findings: int = 0
    evidence: RecommendationEvidence = field(default_factory=RecommendationEvidence)
    rejected_candidates: List[str] = field(default_factory=list)
    verifications: List[VerificationSource] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    commands: List[PackageManagerCommand] = field(default_factory=list)
    verified_date: datetime = field(default_factory=datetime.now)

    @property
    def package(self) -> str:
        return self.package_name

    @property
    def minimum_secure_version(self) -> Optional[str]:
        return self.minimum_known_safe

    @property
    def latest_stable_version(self) -> Optional[str]:
        return self.latest_stable

    @property
    def latest_available_version(self) -> Optional[str]:
        return self.latest_stable

    @property
    def upgrade_command(self) -> str:
        if isinstance(self.commands, list) and self.commands:
            rec_cmds = [c for c in self.commands if getattr(c, 'recommended', False)]
            if rec_cmds:
                return getattr(rec_cmds[0], 'command', str(rec_cmds[0]))
            return getattr(self.commands[0], 'command', str(self.commands[0]))
        elif isinstance(self.commands, dict):
            return self.commands.get("upgrade", self.commands.get("default", ""))
        if self.recommended_version:
            from pulse.remediation.command_generator import generate_upgrade_command
            return generate_upgrade_command(self.package_name, self.ecosystem, self.recommended_version)
        return "Manual upgrade review required"

    @property
    def evidence_sources(self) -> List[str]:
        return self.sources
