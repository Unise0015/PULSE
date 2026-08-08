import time
import platform
import hashlib
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.services.enrichment_pipeline import (
    EnrichmentPipeline, EnrichmentResult, EnrichmentMetrics,
    VersionEnricher, NVDEnricher, EPSSEnricher, MITREEnricher,
    KEVEnricher, RiskEnricher, ExploitEnricher, AttackPathEnricher
)
import pulse.history as history_mod
from pulse.security_advisor import SecurityAdvisor
from pulse.vulnerability.osv_provider import OSVProvider
from pulse.vulnerability.nvd_provider import NVDProvider
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse import __version__

def compute_packages_fingerprint(packages) -> str:
    sorted_pkgs = sorted(packages, key=lambda p: (p.ecosystem or "", p.name or "", p.version or ""))
    pkg_strings = [f"{p.ecosystem}:{p.name}@{p.version}" for p in sorted_pkgs]
    hasher = hashlib.sha256()
    hasher.update("\n".join(pkg_strings).encode('utf-8'))
    return hasher.hexdigest()

class WebsiteService:
    """Orchestrates website scanning and technology fingerprint correlation."""
    
    def run(self, console, url: str) -> ScanResult:
        console.print(f"\n[bold]Fingerprinting Website:[/bold] {url}")
        
        start_time = time.time()
        analyzer = WebsiteFingerprintAnalyzer()
        
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            task = progress.add_task("[yellow]Analyzing headers and DOM...[/yellow]", total=None)
            assessment = analyzer.scan(url)
            progress.update(task, completed=1, description="[green]Website analysis completed[/green]")
            
        duration = round(time.time() - start_time, 2)
        
        scan_result = ScanResult(
            timestamp=datetime.now(),
            hostname=platform.node(),
            tool_version=__version__,
            packages_scanned=0,
            attack_surface_score=0,
            scan_duration_seconds=duration,
            website_assessment=assessment,
            target_type="website",
            target_id=url,
            target_fingerprint=url
        )
        
        return scan_result

    def analyze_technologies(self, console, scan: ScanResult) -> None:
        if not scan.website_assessment:
            return
            
        from pulse.domain.models import FindingSourceType, VersionMetadata, RegistryType, BranchStatus, CorrelationStatus
        scan.website_assessment.correlation_status = CorrelationStatus.RUNNING
        from pulse.website.technology_resolver import resolve_technology
        from pulse.website.version_resolver import resolve_version, VersionResolutionStatus
        from pulse.website.lookup_strategy import determine_lookup_strategy, LookupStrategyType
        from pulse.website.cve_mapper import get_cpe_candidate, get_osv_package_for_tech
        from pulse.website.confidence_correlation import should_correlate
        from pulse.website.scoring import get_confidence_multiplier, calculate_adjusted_risk
        from pulse.website.remediation import get_upgrade_recommendation
        from pulse.enrichment.nvd.correlator import NVDCorrelationEngine
        from pulse.correlation.models import CorrelationResult, CPECandidate, ResolverMatchType
        
        eligible = []
        skipped = []
        tech_to_findings = {} # maps tech_key -> findings list
        tech_to_pkg = {} # maps tech_key -> PackageInfo
        
        # Prepare lookup queues
        osv_packages = []
        nvd_correlation_results = []
        
        for tech in scan.website_assessment.technologies:
            if not tech.correlation_supported:
                skipped.append(f"{tech.name} (correlation not supported by signature)")
                continue
                
            tech_key = resolve_technology(tech.name)
            if not tech_key:
                skipped.append(f"{tech.name} (unsupported technology)")
                continue
                
            # Mutate tech.name to normalized key so downstream layers (like history) get normalized keys
            tech.name = tech_key
            
            normalized_version, version_status = resolve_version(tech_key, tech.version, tech.confidence)
            do_lookup, show_warning = should_correlate(tech.confidence)
            
            if not do_lookup:
                skipped.append(f"{tech.name} (confidence {tech.confidence} < 40)")
                continue
                
            strategy = determine_lookup_strategy(tech_key)
            
            # Record eligible
            version_disp = normalized_version if normalized_version else "Unknown"
            eligible.append(f"{tech.name} {version_disp} (Strategy: {strategy.value.upper()})")
            
            # Map inputs for lookup
            from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
            catalog_entry = TECHNOLOGY_CATALOG.get(tech_key)
            display_name = catalog_entry.get("display_name", tech.name) if catalog_entry else tech.name
            
            # Create PackageInfo representing the technology
            pkg_name = catalog_entry.get("package", tech_key) if catalog_entry else tech_key
            eco = catalog_entry.get("ecosystem", "website") if catalog_entry else "website"
            
            # If strategy is OSV_ONLY or OSV_AND_NVD, map to OSV package
            if strategy in (LookupStrategyType.OSV_ONLY, LookupStrategyType.OSV_AND_NVD):
                osv_map = get_osv_package_for_tech(tech_key)
                if osv_map and normalized_version:
                    pkg_name_osv, ecosystem_osv = osv_map
                    pkg = PackageInfo(name=pkg_name_osv, version=normalized_version, ecosystem=ecosystem_osv, dependency_type="DIRECT")
                    osv_packages.append((tech_key, pkg))
                    tech_to_pkg[tech_key] = pkg
                    
            # If strategy is NVD_ONLY or OSV_AND_NVD, map to CPE candidate
            if strategy in (LookupStrategyType.NVD_ONLY, LookupStrategyType.OSV_AND_NVD):
                cpe_candidate_str = get_cpe_candidate(tech_key, normalized_version)
                if cpe_candidate_str:
                    parts = cpe_candidate_str.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        cpe_template = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*"
                        candidate = CPECandidate(
                            cpe_template=cpe_template,
                            detected_version=normalized_version,
                            resolved_cpe=cpe_candidate_str,
                            confidence=tech.confidence,
                            source="catalog",
                            vendor=vendor,
                            product=product,
                            exact_version_match=True,
                            match_type=ResolverMatchType.EXACT
                        )
                        corr_result = CorrelationResult(
                            technology=tech_key,
                            inventory_technology_key=tech_key,
                            candidates=[candidate],
                            selected_candidate=candidate,
                            resolution_confidence=tech.confidence
                        )
                        nvd_correlation_results.append((tech_key, corr_result))
                        
            # Ensure at least a dummy package exists for display/remediation if no lookup mapped it
            if tech_key not in tech_to_pkg:
                tech_to_pkg[tech_key] = PackageInfo(
                    name=pkg_name,
                    version=normalized_version or "Unknown",
                    ecosystem=eco,
                    dependency_type="DIRECT"
                )
                
        console.print("\n[bold]Analyzing eligible technologies...[/bold]\n")
        
        if eligible:
            console.print("Eligible:")
            for item in eligible:
                console.print(f"- {item}")
        
        if skipped:
            console.print("\nSkipped:")
            for item in skipped:
                console.print(f"- {item}")
                
        console.print()
        
        all_findings = []
        osv_provider = OSVProvider()
        nvd_provider = NVDProvider()
        
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            
            # 1. OSV Matching
            osv_succeeded = True
            if osv_packages:
                task_osv = progress.add_task("[yellow]Matching vulnerabilities (OSV)...[/yellow]", total=None)
                pkgs_list = [pkg for _, pkg in osv_packages]
                try:
                    osv_findings = osv_provider.lookup_packages(pkgs_list)
                    for f in osv_findings:
                        raw = f.description or ""
                        f.summary = raw[:250] + "..." if len(raw) > 250 else raw
                        for tech_key, pkg in osv_packages:
                            if pkg.name.lower() == f.package.name.lower() and pkg.version == f.package.version:
                                f.source_type = FindingSourceType.WEBSITE
                                f.source_asset = tech_key
                                if tech_key not in tech_to_findings:
                                    tech_to_findings[tech_key] = []
                                tech_to_findings[tech_key].append(f)
                                all_findings.append(f)
                                break
                    progress.update(task_osv, completed=1, description=f"[green]OSV Matching[/green] found {len(osv_findings)} vulnerabilities")
                except Exception as e:
                    osv_succeeded = False
                    import logging
                    logging.getLogger(__name__).error(f"OSV matching failed: {e}")
                    progress.update(task_osv, completed=1, description="[red]OSV Matching failed[/red]")
                
            # 2. NVD CPE Matching
            nvd_succeeded = True
            if nvd_correlation_results:
                task_nvd = progress.add_task("[yellow]Matching vulnerabilities (NVD CPE)...[/yellow]", total=None)
                engine = NVDCorrelationEngine()
                results_list = [res for _, res in nvd_correlation_results]
                try:
                    correlated_vulns, _ = engine.correlate(results_list)
                    nvd_count = 0
                    for cv in correlated_vulns:
                        for tech_key, corr_res in nvd_correlation_results:
                            if corr_res.technology == cv.technology_name:
                                pkg = tech_to_pkg.get(tech_key)
                                if pkg:
                                    finding = VulnerabilityFinding(
                                        package=pkg,
                                        cve_id=cv.cve_id,
                                        cvss_score=cv.cvss_v3_score or 0.0,
                                        cvss_severity=cv.severity or "UNKNOWN",
                                        epss_score=0.0,
                                        epss_percent="0%",
                                        kev_match=False,
                                        risk_heat_score=0,
                                        description=cv.description or "",
                                        fix_version=None,
                                        source="NVD",
                                        published_date=cv.published_date.strftime("%Y-%m-%d") if cv.published_date else None,
                                        last_modified_date=None,
                                        nvd_url=cv.nvd_url or "",
                                        cwe=cv.cwe,
                                        source_type=FindingSourceType.WEBSITE,
                                        source_asset=tech_key
                                    )
                                    if tech_key not in tech_to_findings:
                                        tech_to_findings[tech_key] = []
                                    tech_to_findings[tech_key].append(finding)
                                    all_findings.append(finding)
                                    nvd_count += 1
                                break
                    progress.update(task_nvd, completed=1, description=f"[green]NVD CPE Matching[/green] found {nvd_count} vulnerabilities")
                except Exception as e:
                    nvd_succeeded = False
                    import logging
                    logging.getLogger(__name__).error(f"NVD matching failed: {e}")
                    progress.update(task_nvd, completed=1, description="[red]NVD CPE Matching failed[/red]")
                
            # 3. Fetching registry info for version intelligence
            supported_ecosystems = (
                "pypi", "python", "npm", "node", "node.js",
                "crates.io", "rust", "cargo", "rubygems", "ruby",
                "composer", "php", "packagist", "maven", "java",
                "nuget", ".net", "dotnet"
            )
            registry_packages = [pkg for pkg in tech_to_pkg.values() if pkg.ecosystem and pkg.ecosystem.lower() in supported_ecosystems]
            if registry_packages:
                # Custom stage pipeline: Registry Version Enrichment
                reg_pipeline = EnrichmentPipeline(stages=[VersionEnricher])
                reg_pipeline.run(registry_packages, progress=progress)
                
            # Run remaining enrichment stages on findings
            if all_findings:
                enrich_result = EnrichmentResult(
                    findings=all_findings,
                    attack_paths=[],
                    packages=registry_packages,
                    metrics=EnrichmentMetrics()
                )
                
                stages = [
                    NVDEnricher,
                    EPSSEnricher,
                    MITREEnricher,
                    KEVEnricher,
                    RiskEnricher,
                    ExploitEnricher,
                    AttackPathEnricher
                ]
                
                for stage_cls in stages:
                    try:
                        stage = stage_cls()
                        stage.enrich(enrich_result, progress=progress)
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).error(f"Enrichment stage {stage_cls.__name__} failed: {e}")
                
                # Retrieve generated attack paths
                scan.attack_paths = enrich_result.attack_paths
                
                # Apply Confidence Weighting & Risk adjustments
                task_score = progress.add_task("[yellow]Applying Confidence Weighting...[/yellow]", total=None)
                for finding in all_findings:
                    tech_item = next((t for t in scan.website_assessment.technologies if resolve_technology(t.name) == finding.source_asset), None)
                    if tech_item:
                        mult = get_confidence_multiplier(tech_item.evidence)
                        finding.detection_confidence = tech_item.confidence
                        finding.source_evidence = [f"{ev.method.value}: {ev.source}" for ev in tech_item.evidence]
                        finding.risk_heat_score = calculate_adjusted_risk(finding.risk_heat_score, mult)
                        
                all_findings.sort(key=lambda x: x.risk_heat_score, reverse=True)
                progress.update(task_score, completed=1, description="[green]Weighting & Scoring completed[/green]")
                
        # Generate upgrade advisories for each technology
        for tech_key, pkg in tech_to_pkg.items():
            tech_findings = tech_to_findings.get(tech_key, [])
            
            rec = None
            if pkg.ecosystem and pkg.ecosystem.lower() in supported_ecosystems and getattr(pkg, "version_metadata", None):
                try:
                    reg_provider = VersionIntelligenceService()
                    rec = reg_provider.get_security_fix_version(pkg, pkg.version, tech_findings)
                except Exception:
                    pass
            
            if not rec:
                rec = get_upgrade_recommendation(tech_key, pkg.version, tech_findings)
            
            tech_item = next((t for t in scan.website_assessment.technologies if resolve_technology(t.name) == tech_key), None)
            from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
            catalog_entry = TECHNOLOGY_CATALOG.get(tech_key)
            display_name = catalog_entry.get("display_name", tech_key) if catalog_entry else tech_key
            
            if not pkg.version_metadata:
                normalized_version, version_status = resolve_version(tech_key, tech_item.version if tech_item else None, tech_item.confidence if tech_item else 100)
                pkg.version_metadata = VersionMetadata(
                    current_version=pkg.version,
                    latest_stable_version=rec.latest_stable_version if rec else None,
                    latest_security_fix=rec.latest_security_fix if rec else None,
                    minimum_safe_version=rec.minimum_safe_version if rec else None,
                    latest_lts_version=None,
                    canonical_name=tech_key,
                    display_name=display_name,
                    source_registry=RegistryType.UNKNOWN,
                    source_confidence="offline",
                    registry_available=False,
                    verification_state="VERIFIED" if version_status == VersionResolutionStatus.VERIFIED else "UNVERIFIED",
                    branch_status=BranchStatus.UNKNOWN,
                    source_timestamp=datetime.now(),
                    recommendation=rec
                )
            else:
                pkg.version_metadata.recommendation = rec
                
        # Compute Attack Surface Score
        attack_surface_score = 0
        if all_findings:
            avg_risk = sum(f.risk_heat_score for f in all_findings) // len(all_findings)
            kev_penalty = sum(10 for f in all_findings if f.kev_match)
            attack_surface_score = min(100, avg_risk + kev_penalty)
            
        scan.findings = all_findings
        scan.packages_scanned = len(tech_to_pkg)
        scan.attack_surface_score = attack_surface_score
        
        # Build target fingerprint from package/version list
        sorted_keys = sorted(tech_to_pkg.keys())
        target_fp_raw = "\n".join(f"{k}:{tech_to_pkg[k].version}" for k in sorted_keys)
        scan.target_fingerprint = hashlib.sha256(target_fp_raw.encode("utf-8")).hexdigest()
        

        
        # Calculate Correlation metrics and status
        succeeded_techs = 0
        failed_techs = 0
        for tech_key in tech_to_pkg.keys():
            strategy = determine_lookup_strategy(tech_key)
            if strategy == LookupStrategyType.OSV_ONLY:
                if osv_succeeded:
                    succeeded_techs += 1
                else:
                    failed_techs += 1
            elif strategy == LookupStrategyType.NVD_ONLY:
                if nvd_succeeded:
                    succeeded_techs += 1
                else:
                    failed_techs += 1
            elif strategy == LookupStrategyType.OSV_AND_NVD:
                if osv_succeeded and nvd_succeeded:
                    succeeded_techs += 1
                elif osv_succeeded or nvd_succeeded:
                    succeeded_techs += 1
                else:
                    failed_techs += 1

        scan.website_assessment.correlated_technologies = succeeded_techs
        scan.website_assessment.failed_technologies = failed_techs

        if len(tech_to_pkg) == 0:
            scan.website_assessment.correlation_status = CorrelationStatus.COMPLETED
        else:
            if failed_techs > 0 and succeeded_techs > 0:
                scan.website_assessment.correlation_status = CorrelationStatus.PARTIAL
            elif failed_techs > 0 and succeeded_techs == 0:
                scan.website_assessment.correlation_status = CorrelationStatus.FAILED
            else:
                scan.website_assessment.correlation_status = CorrelationStatus.COMPLETED
        scan.website_assessment.correlation_completed_at = datetime.now()
        
        if not getattr(scan, "_reconstructing", False):
            history = history_mod.HistoryService()
            delta = history.get_posture_delta(scan)
            advisor = SecurityAdvisor()
            scan._advisor_report = advisor.analyze(scan)
            scan._delta = delta

            from pulse.reporting.report_service import ReportService
            ReportService.create_scan_report(scan, posture_delta=delta, advisor=advisor)
        
        return scan
