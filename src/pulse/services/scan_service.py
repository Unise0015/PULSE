import time
import platform
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn

from pulse.domain.models import ScanResult, VulnerabilityFinding, PluginExecutionStatus, PluginDiagnostics
from pulse.ecosystems import registry
from pulse.ecosystems.base import ScanContext, ScannerConfig, ScanPhase
from pulse.services.enrichment_pipeline import EnrichmentPipeline
import pulse.history as history_mod
import pulse.ui as ui
from pulse.security_advisor import SecurityAdvisor
from pulse.supply_chain.dependency_analyzer import DependencyAnalyzer
from pulse import __version__

def compute_file_metadata_fingerprint(current_dir: Path) -> str:
    lockfiles = [
        "requirements.txt", "package-lock.json", "package.json",
        "Cargo.lock", "go.mod", "go.sum", "Gemfile.lock", "composer.lock"
    ]
    meta_parts = []
    for f in sorted(lockfiles):
        p = current_dir / f
        if p.exists() and p.is_file():
            try:
                st = p.stat()
                meta_parts.append(f"{f}:{st.st_size}:{st.st_mtime}")
            except Exception:
                pass
    if not meta_parts:
        return "empty"
    hasher = hashlib.sha256()
    hasher.update("\n".join(meta_parts).encode('utf-8'))
    return hasher.hexdigest()

def compute_packages_fingerprint(packages) -> str:
    sorted_pkgs = sorted(packages, key=lambda p: (p.ecosystem or "", p.name or "", p.version or ""))
    pkg_strings = [f"{p.ecosystem}:{p.name}@{p.version}" for p in sorted_pkgs]
    hasher = hashlib.sha256()
    hasher.update("\n".join(pkg_strings).encode('utf-8'))
    return hasher.hexdigest()

class ScanService:
    """Orchestrates project discovery and scanning."""
    
    def run(self, console) -> ScanResult:
        from pulse.state import AppState
        console.print("\n[bold]Auto-Discovering Packages...[/bold]")
        
        start_time = time.time()
        
        all_packages = []
        findings = []
        edges = []
        detected_ecosystems = []
        plugin_diagnostics = {}
        

        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            # 1. Discovering packages
            task1 = progress.add_task("[yellow]Discovering packages...[/yellow]", total=None)
            
            from pulse.config import get_setting
            cfg = ScannerConfig(
                default_severity=get_setting("DEFAULT_SEVERITY", "high"),
                default_output=get_setting("DEFAULT_OUTPUT", "table"),
                nvd_api_key=get_setting("NVD_API_KEY", "")
            )
            
            logger = logging.getLogger("pulse")
            context = ScanContext(
                root=Path("."),
                config=cfg,
                cache=None,
                history=None,
                logger=logger
            )
            context.phase = ScanPhase.DISCOVERY
            
            plugins = registry.detect(context)
            for plugin in plugins:
                try:
                    res = plugin.discover(context)
                    all_packages.extend(res.packages)
                    edges.extend(res.dependency_edges)
                    plugin_diagnostics[plugin.manifest.id] = res.diagnostics
                    if res.packages:
                        # Backward compatibility for display names:
                        detected_ecosystems.append(plugin.manifest.name)
                except Exception as e:
                    logger.error(f"Plugin {plugin.manifest.id} discovery failed: {e}", exc_info=True)
                    plugin_diagnostics[plugin.manifest.id] = PluginDiagnostics(
                        status=PluginExecutionStatus.FAILED,
                        errors=[f"Plugin execution crashed: {e}"]
                    )
                    
            progress.update(task1, completed=1, description=f"[green]Discovered[/green] {len(all_packages)} packages")

            # 2. Run Enrichment Pipeline
            pipeline = EnrichmentPipeline()
            pipeline_progress = progress if AppState.DEBUG_MODE else None
            enrich_result = pipeline.run(all_packages, progress=pipeline_progress, context=context)
            findings = enrich_result.findings
        
        # Calculate Attack Surface Score
        attack_surface_score = EnrichmentPipeline.calculate_attack_surface_score(findings)
            
        duration = round(time.time() - start_time, 2)
        
        scan_result = ScanResult(
            timestamp=datetime.now(),
            hostname=platform.node(),
            tool_version=__version__,
            packages_scanned=len(all_packages),
            attack_surface_score=attack_surface_score,
            scan_duration_seconds=duration,
            findings=findings,
            detected_ecosystems=detected_ecosystems,
            plugin_diagnostics=plugin_diagnostics,
            target_type="project",
            target_id=Path(".").resolve().as_posix(),
            target_fingerprint=compute_file_metadata_fingerprint(Path("."))
        )
        
        scan_result.attack_paths = enrich_result.attack_paths
        
        trees = DependencyAnalyzer.build_generic_tree(all_packages, edges, scan_result.findings)
        scan_result.dependency_trees = trees
        scan_result.supply_chain_metrics = DependencyAnalyzer.compute_metrics(trees)
        
        history = history_mod.HistoryService()
        delta = history.get_posture_delta(scan_result)
        scan_result._delta = delta

        from pulse.version_intelligence.recommendation_engine import populate_scan_recommendations
        populate_scan_recommendations(scan_result)

        # Security Advisor — risk projection and Fix First panel
        advisor = SecurityAdvisor()
        advisor_report = advisor.analyze(scan_result)
        scan_result._advisor_report = advisor_report

        from pulse.reporting.report_service import ReportService
        ReportService.create_scan_report(scan_result, posture_delta=delta, advisor=advisor)

        return scan_result
