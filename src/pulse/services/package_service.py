import time
import platform
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn

from pulse.domain.models import ScanResult, VulnerabilityFinding
from pulse.services.enrichment_pipeline import EnrichmentPipeline, compute_packages_fingerprint
import pulse.history as history_mod
import pulse.ui as ui
from pulse.security_advisor import SecurityAdvisor
from pulse.supply_chain.dependency_analyzer import DependencyAnalyzer
from pulse import __version__

class PackageService:
    """Orchestrates scanning of specific individual packages."""
    
    def run(self, console, packages, target_type: str = "global", target_id: str = "global") -> ScanResult:
        from pulse.state import AppState
        
        start_time = time.time()
        findings = []
        
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            if AppState.DEBUG_MODE:
                # Debug mode: show individual enrichment stage messages
                pipeline = EnrichmentPipeline()
                enrich_result = pipeline.run(packages, progress=progress)
            else:
                # Normal mode: single spinner, no individual stage noise
                task = progress.add_task("[yellow]Scanning package...[/yellow]", total=None)
                pipeline = EnrichmentPipeline()
                enrich_result = pipeline.run(packages, progress=None)
                pass
            findings = enrich_result.findings
        
        attack_surface_score = EnrichmentPipeline.calculate_attack_surface_score(findings)
            
        duration = round(time.time() - start_time, 2)
        
        eco_names = {
            "python": "Python", "pypi": "Python",
            "npm": "Node.js", "node": "Node.js",
            "crates.io": "Rust", "rust": "Rust",
            "go": "Go",
            "rubygems": "Ruby", "ruby": "Ruby",
            "packagist": "Composer", "composer": "Composer"
        }
        detected = list(set(eco_names.get(p.ecosystem.lower(), p.ecosystem) for p in packages if p.ecosystem))

        scan_result = ScanResult(
            timestamp=datetime.now(),
            hostname=platform.node(),
            tool_version=__version__,
            packages_scanned=len(packages),
            attack_surface_score=attack_surface_score,
            scan_duration_seconds=duration,
            findings=findings,
            detected_ecosystems=detected,
            target_type=target_type,
            target_id=target_id,
            target_fingerprint=compute_packages_fingerprint(packages)
        )
        
        scan_result.attack_paths = enrich_result.attack_paths
        
        # Build flat tree for targeted scans since we don't have lockfile context
        trees = DependencyAnalyzer.build_flat_tree(packages, scan_result.findings)
        scan_result.dependency_trees = trees
        scan_result.supply_chain_metrics = DependencyAnalyzer.compute_metrics(trees)
        
        history = history_mod.HistoryService()
        delta = history.get_posture_delta(scan_result)
        scan_result._delta = delta
        
        from pulse.version_intelligence.recommendation_engine import populate_scan_recommendations
        populate_scan_recommendations(scan_result)
        
        advisor = SecurityAdvisor()
        scan_result._advisor_report = advisor.analyze(scan_result)
        
        from pulse.reporting.report_service import ReportService
        ReportService.create_scan_report(scan_result, posture_delta=delta, advisor=advisor)
        
        return scan_result
