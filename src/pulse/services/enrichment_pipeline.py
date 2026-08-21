import time
import logging
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Type
from rich.progress import Progress

from pulse.domain.models import PackageInfo, VulnerabilityFinding, AttackPath
from pulse.vulnerability.osv_provider import OSVProvider
from pulse.vulnerability.nvd_provider import NVDProvider
from pulse.vulnerability.threat_intel import EPSSProvider, KEVProvider, RiskCalculator
from pulse.vulnerability.threat_mapping import ThreatMapper
from pulse.vulnerability.exploit_intelligence import ExploitIntelligenceAnalyzer
from pulse.vulnerability.version_intelligence import VersionIntelligenceService
from pulse.supply_chain.attack_paths import AttackPathAnalyzer
from pulse.security_advisor import SecurityAdvisor

logger = logging.getLogger(__name__)

def compute_packages_fingerprint(packages: List[PackageInfo]) -> str:
    sorted_pkgs = sorted(packages, key=lambda p: (p.ecosystem or "", p.name or "", p.version or ""))
    pkg_strings = [f"{p.ecosystem}:{p.name}@{p.version}" for p in sorted_pkgs]
    hasher = hashlib.sha256()
    hasher.update("\n".join(pkg_strings).encode('utf-8'))
    return hasher.hexdigest()

@dataclass
class EnrichmentMetrics:
    osv_matches: int = 0
    nvd_matches: int = 0
    kev_matches: int = 0
    attack_paths: int = 0
    enriched_findings: int = 0
    elapsed_ms: int = 0

@dataclass
class EnrichmentResult:
    findings: List[VulnerabilityFinding]
    attack_paths: List[AttackPath]
    packages: List[PackageInfo]
    metrics: EnrichmentMetrics
    warnings: List[str] = field(default_factory=list)

class BaseEnricher(ABC):
    """Abstract interface for all individual enrichment stages."""
    
    @abstractmethod
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        pass

class VersionEnricher(BaseEnricher):
    """Enriches packages with registry metadata (latest versions)."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.packages:
            return
        if progress:
            task = progress.add_task("[yellow]Fetching package registry data...[/yellow]", total=None)
        reg_provider = VersionIntelligenceService()
        reg_provider.enrich_packages(data.packages)
        if progress:
            progress.update(task, completed=1, description="[green]Registry data[/green] collected")

class OSVEnricher(BaseEnricher):
    """Matches packages to vulnerabilities using OSV API and NVD CPE correlation."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.packages:
            return
        from pulse.ecosystems.base import ScanPhase
        if context:
            context.phase = ScanPhase.CORRELATION
            
        if progress:
            task = progress.add_task("[yellow]Matching vulnerabilities (OSV / NVD)...[/yellow]", total=None)
        
        osv_provider = OSVProvider()
        findings = osv_provider.lookup_packages(data.packages)
        for f in findings:
            raw = f.description or ""
            f.summary = raw[:250] + "..." if len(raw) > 250 else raw
            
        data.findings.extend(findings)
        data.metrics.osv_matches = len(findings)

        # Check for packages with 0 OSV findings that have known CPE entries in catalog or technology definitions
        packages_with_findings = {f.package.name.lower() for f in data.findings if f.package and f.package.name}
        unmatched_packages = [p for p in data.packages if p.name and p.name.lower() not in packages_with_findings]
        
        if unmatched_packages:
            try:
                from pulse.enrichment.nvd.cpe_resolver import TieredCPEResolver
                from pulse.enrichment.nvd.correlator import NVDCorrelationEngine
                from pulse.correlation.models import CorrelationResult, CPECandidate, ResolverMatchType
                from pulse.domain.models import FindingSourceType
                
                cpe_resolver = TieredCPEResolver()
                cpe_results = []
                pkg_map = {}
                for pkg in unmatched_packages:
                    norm = pkg.name.lower()
                    resolution = cpe_resolver.resolve(pkg.name, pkg.ecosystem)
                    
                    if resolution:
                        ver_str = pkg.version or "*"
                        cpe_str = f"{resolution.cpe_uri}:{ver_str}:*:*:*:*:*:*:*"
                        candidate = CPECandidate(
                            cpe_template=f"{resolution.cpe_uri}:*:*:*:*:*:*:*:*",
                            detected_version=pkg.version,
                            resolved_cpe=cpe_str,
                            confidence=resolution.confidence,
                            source=resolution.source,
                            vendor=resolution.vendor,
                            product=resolution.product,
                            exact_version_match=bool(pkg.version),
                            match_type=ResolverMatchType.EXACT
                        )
                        cpe_res = CorrelationResult(
                            technology=pkg.name,
                            inventory_technology_key=norm,
                            candidates=[candidate],
                            selected_candidate=candidate,
                            resolution_confidence=resolution.confidence
                        )
                        cpe_results.append(cpe_res)
                        pkg_map[norm] = pkg
                        
                if cpe_results:
                    engine = NVDCorrelationEngine()
                    cpe_vulns, _ = engine.correlate(cpe_results)
                    for cv in cpe_vulns:
                        orig_pkg = pkg_map.get(cv.technology_name.lower()) or PackageInfo(name=cv.technology_name, version=cv.version or "Unknown", ecosystem="NVD")
                        data.findings.append(VulnerabilityFinding(
                            package=orig_pkg,
                            cve_id=cv.cve_id,
                            cvss_score=cv.cvss_v3_score or 0.0,
                            cvss_severity=cv.severity or "UNKNOWN",
                            description=cv.description or "",
                            summary=cv.description[:247] + "..." if len(cv.description or "") > 250 else (cv.description or ""),
                            source="NVD",
                            published_date=cv.published_date.strftime("%Y-%m-%d") if cv.published_date else None,
                            nvd_url=cv.nvd_url or f"https://nvd.nist.gov/vuln/detail/{cv.cve_id}",
                            cwe=cv.cwe,
                            source_type=FindingSourceType.PACKAGE,
                            source_asset=orig_pkg.name
                        ))
            except Exception as e:
                logger.debug("NVD CPE correlation in OSVEnricher failed: %s", e)
        
        if progress:
            progress.update(task, completed=1, description=f"[green]Vulnerability Matching[/green] found {len(data.findings)} vulnerabilities")

class NVDEnricher(BaseEnricher):
    """Enriches vulnerabilities with NVD metadata."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        from pulse.ecosystems.base import ScanPhase
        if context:
            context.phase = ScanPhase.ENRICHMENT
            
        if progress:
            task = progress.add_task("[yellow]Enriching with NVD...[/yellow]", total=None)
            
        nvd_provider = NVDProvider()
        # Filter to findings that came from OSV to enrich them
        osv_findings = [f for f in data.findings if f.source == "OSV"]
        if osv_findings:
            nvd_provider.enrich_findings(osv_findings)
            for f in osv_findings:
                if f.description and (not f.summary or len(f.description) > len(f.summary or "")):
                    raw = f.description
                    f.summary = raw[:250] + "..." if len(raw) > 250 else raw
                    
        # Update metrics
        data.metrics.nvd_matches = len([f for f in data.findings if f.cvss_score > 0.0])
        
        if progress:
            progress.update(task, completed=1, description="[green]NVD Enrichment[/green] completed")

class EPSSEnricher(BaseEnricher):
    """Enriches findings with EPSS scores."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        from pulse.ecosystems.base import ScanPhase
        if context:
            context.phase = ScanPhase.SCORING
            
        if progress:
            task = progress.add_task("[yellow]Fetching EPSS scores...[/yellow]", total=None)
            
        epss_provider = EPSSProvider()
        epss_provider.enrich_findings(data.findings)
        
        if progress:
            progress.update(task, completed=1, description="[green]EPSS Enrichment[/green] completed")

class MITREEnricher(BaseEnricher):
    """Maps findings to MITRE ATT&CK techniques."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        if progress:
            task = progress.add_task("[yellow]Mapping MITRE ATT&CK Techniques...[/yellow]", total=None)
            
        threat_mapper = ThreatMapper()
        threat_mapper.enrich_findings(data.findings)
        
        if progress:
            progress.update(task, completed=1, description="[green]ATT&CK Mapping[/green] completed")

class KEVEnricher(BaseEnricher):
    """Correlates findings with the CISA KEV catalog."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        if progress:
            task = progress.add_task("[yellow]Matching KEV entries...[/yellow]", total=None)
            
        kev_provider = KEVProvider()
        kev_provider.enrich_findings(data.findings)
        data.metrics.kev_matches = sum(1 for f in data.findings if f.kev_match)
        
        if progress:
            progress.update(task, completed=1, description="[green]KEV Matching[/green] completed")

class ExploitIntelEnricher(BaseEnricher):
    """Enriches findings with exploit intelligence (PoC, maturity)."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        if progress:
            task = progress.add_task("[yellow]Analyzing Exploit Intelligence...[/yellow]", total=None)
            
        ExploitIntelligenceAnalyzer.enrich_findings(data.findings)
        
        if progress:
            progress.update(task, completed=1, description="[green]Exploit Intelligence[/green] completed")

class RiskEnricher(BaseEnricher):
    """Calculates risk heat scores for all findings."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        if progress:
            task = progress.add_task("[yellow]Calculating Risk Scores...[/yellow]", total=None)
            
        for finding in data.findings:
            RiskCalculator.calculate_risk(finding)
            
        # Sort descending by risk score
        data.findings.sort(key=lambda x: x.risk_heat_score, reverse=True)
        data.metrics.enriched_findings = len(data.findings)
        
        if progress:
            progress.update(task, completed=1, description="[green]Risk Scoring[/green] completed")



class AttackPathEnricher(BaseEnricher):
    """Generates attack paths based on findings."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        # Construct temporary ScanResult for AttackPathAnalyzer compatibility
        from pulse.domain.models import ScanResult
        from datetime import datetime
        import platform
        from pulse import __version__
        
        dummy_scan = ScanResult(
            timestamp=datetime.now(),
            hostname=platform.node(),
            tool_version=__version__,
            packages_scanned=len(data.packages),
            attack_surface_score=0,
            scan_duration_seconds=0.0,
            findings=data.findings
        )
        
        AttackPathAnalyzer.generate(dummy_scan)
        data.attack_paths.extend(dummy_scan.attack_paths)
        data.metrics.attack_paths = len(dummy_scan.attack_paths)

class RemediationEnricher(BaseEnricher):
    """Generates security fix recommendations."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        from pulse.domain.models import ScanResult
        from datetime import datetime
        import platform
        from pulse import __version__
        
        dummy_scan = ScanResult(
            timestamp=datetime.now(),
            hostname=platform.node(),
            tool_version=__version__,
            packages_scanned=len(data.packages),
            attack_surface_score=0,
            scan_duration_seconds=0.0,
            findings=data.findings
        )
        
        advisor = SecurityAdvisor()
        advisor_report = advisor.analyze(dummy_scan)
        # Attach the report to the result metadata
        data.findings = dummy_scan.findings
        # We can store the advisor report in metrics or diagnostics as needed
        data.metrics.enriched_findings = len(data.findings)

# All standard stages run in default pipeline
DEFAULT_STAGES: List[Type[BaseEnricher]] = [
    VersionEnricher,
    OSVEnricher,
    NVDEnricher,
    EPSSEnricher,
    MITREEnricher,
    KEVEnricher,
    ExploitIntelEnricher,
    RiskEnricher,
    AttackPathEnricher,
    RemediationEnricher
]

class EnrichmentPipeline:
    """Consolidated, stage-driven, and fault-tolerant dependency enrichment pipeline."""
    
    def __init__(self, stages: Optional[List[Type[BaseEnricher]]] = None):
        self.stages = stages or DEFAULT_STAGES

    def run(self, 
            packages: List[PackageInfo], 
            progress: Optional[Progress] = None, 
            context: Any = None) -> EnrichmentResult:
        
        start_time = time.time()
        result = EnrichmentResult(
            findings=[],
            attack_paths=[],
            packages=packages,
            metrics=EnrichmentMetrics()
        )
        
        main_task = None
        if progress:
            main_task = progress.add_task("[bold blue]Vulnerability Intelligence Pipeline[/bold blue]", total=len(self.stages))
        
        for stage_cls in self.stages:
            if progress and main_task is not None:
                progress.update(main_task, description=f"[bold blue]Running {stage_cls.__name__}...[/bold blue]")
            try:
                stage = stage_cls()
                # Suppress the nested tasks within stages since we have a main pipeline progress now
                stage.enrich(result, None, context)
            except Exception as e:
                msg = f"Enrichment stage {stage_cls.__name__} failed: {e}"
                logger.error(msg, exc_info=True)
                result.warnings.append(msg)
            
            if progress and main_task is not None:
                progress.advance(main_task)
                
        from pulse.domain.models import deduplicate_and_merge_findings
        result.findings = deduplicate_and_merge_findings(result.findings)
        result.metrics.enriched_findings = len(result.findings)

        elapsed = int((time.time() - start_time) * 1000)
        result.metrics.elapsed_ms = elapsed
        return result

    @staticmethod
    def calculate_attack_surface_score(findings: List[VulnerabilityFinding]) -> int:
        if not findings:
            return 0
        avg_risk = sum(f.risk_heat_score for f in findings) // len(findings)
        kev_penalty = sum(10 for f in findings if f.kev_match)
        return min(100, avg_risk + kev_penalty)
