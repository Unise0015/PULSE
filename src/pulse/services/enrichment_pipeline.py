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

        # Query multi-vendor CPEs and release-qualified Linux Distro OSV for standalone/unmatched packages
        packages_with_findings = {f.package.name.lower() for f in data.findings if f.package and f.package.name}
        unmatched_packages = [p for p in data.packages if p.name and (p.name.lower() not in packages_with_findings or p.ecosystem in ("Standalone", "Standalone Software", "NVD"))]
        
        if unmatched_packages:
            import asyncio
            from pulse.vulnerability.distro_osv import DistroOSVClient
            from pulse.vulnerability.cpe_resolver import CPEResolver
            from pulse.enrichment.nvd.correlator import NVDCorrelationEngine
            from pulse.correlation.models import CorrelationResult, CPECandidate, ResolverMatchType
            from pulse.domain.models import FindingSourceType

            distro_client = DistroOSVClient()
            for pkg in unmatched_packages:
                # 1. Distro OSV queries (Debian:11/12, Alpine:v3.18/v3.19/v3.20, Ubuntu:22.04/24.04, Rocky Linux:9, AlmaLinux:9, Wolfi)
                try:
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    
                    if loop.is_running():
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(asyncio.run, distro_client.query_all_distros(pkg.name, pkg.version or ""))
                            distro_findings = future.result()
                    else:
                        distro_findings = loop.run_until_complete(distro_client.query_all_distros(pkg.name, pkg.version or ""))

                    for df in distro_findings:
                        df.package = pkg
                        df.source_type = FindingSourceType.PACKAGE
                        df.source_asset = pkg.name
                        data.findings.append(df)
                except Exception as e:
                    logger.debug("Distro OSV query failed for %s: %s", pkg.name, e)

                # 2. Multi-Vendor Dynamic CPE Resolution (f5, nginx, igor_sysoev, apache, openssl, etc.)
                try:
                    cpe_candidates_str = CPEResolver.get_cpe_candidates(pkg.name, pkg.version)
                    cpe_results = []
                    for cpe_str in cpe_candidates_str:
                        parts = cpe_str.split(":")
                        vendor = parts[3] if len(parts) > 3 else pkg.name
                        product = parts[4] if len(parts) > 4 else pkg.name
                        candidate = CPECandidate(
                            cpe_template=f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                            detected_version=pkg.version,
                            resolved_cpe=cpe_str,
                            confidence=100,
                            source="cpe_resolver",
                            vendor=vendor,
                            product=product,
                            exact_version_match=bool(pkg.version),
                            match_type=ResolverMatchType.EXACT
                        )
                        cpe_res = CorrelationResult(
                            technology=pkg.name,
                            inventory_technology_key=pkg.name.lower(),
                            candidates=[candidate],
                            selected_candidate=candidate,
                            resolution_confidence=100
                        )
                        cpe_results.append(cpe_res)

                    if cpe_results:
                        engine = NVDCorrelationEngine()
                        cpe_vulns, _ = engine.correlate(cpe_results)
                        seen_cves = {f.cve_id for f in data.findings if f.cve_id}
                        for cv in cpe_vulns:
                            if cv.cve_id in seen_cves:
                                continue
                            seen_cves.add(cv.cve_id)
                            data.findings.append(VulnerabilityFinding(
                                package=pkg,
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
                                source_asset=pkg.name
                            ))
                except Exception as e:
                    logger.debug("Multi-vendor CPE correlation failed for %s: %s", pkg.name, e)
        
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

class ExploitEnricher(BaseEnricher):
    """Enriches findings with exploit maturity / public PoC records."""
    
    def enrich(self, data: EnrichmentResult, progress: Optional[Progress] = None, context: Any = None) -> None:
        if not data.findings:
            return
        ExploitIntelligenceAnalyzer.enrich_findings(data.findings)

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
    RiskEnricher,
    ExploitEnricher,
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
        
        for stage_cls in self.stages:
            try:
                stage = stage_cls()
                stage.enrich(result, progress, context)
            except Exception as e:
                msg = f"Enrichment stage {stage_cls.__name__} failed: {e}"
                logger.error(msg, exc_info=True)
                result.warnings.append(msg)
                
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
