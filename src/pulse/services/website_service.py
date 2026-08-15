import time
import platform
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from rich.progress import Progress, SpinnerColumn, TextColumn

from pulse.domain.models import (
    ScanResult, VulnerabilityFinding, PackageInfo, FindingSourceType,
    CorrelationStatus, TechnologyFingerprint, TechnologyCorrelationResult
)
from pulse.services.enrichment_pipeline import (
    EnrichmentPipeline, EnrichmentResult, EnrichmentMetrics
)
import pulse.history as history_mod
from pulse.security_advisor import SecurityAdvisor
from pulse.version_intelligence.recommendation_engine import populate_scan_recommendations
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.website.capability import (
    evaluate_correlation_eligibility, evaluate_all_eligibilities,
    CorrelationEligibilityStatus, CorrelationEligibility
)
from pulse.website.scoring import get_confidence_multiplier, calculate_adjusted_risk
from pulse.reporting.report_service import ReportService
from pulse import __version__

logger = logging.getLogger(__name__)


def compute_packages_fingerprint(packages) -> str:
    sorted_pkgs = sorted(packages, key=lambda p: (p.ecosystem or "", p.name or "", p.version or ""))
    pkg_strings = [f"{p.ecosystem}:{p.name}@{p.version}" for p in sorted_pkgs]
    hasher = hashlib.sha256()
    hasher.update("\n".join(pkg_strings).encode('utf-8'))
    return hasher.hexdigest()


class WebsiteService:
    """Orchestrates website scanning and canonical technology package correlation."""

    def run(self, console, url: str) -> ScanResult:
        start_time = time.time()
        analyzer = WebsiteFingerprintAnalyzer()
        
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[yellow]Detecting website technologies...[/yellow]", total=None)
            assessment = analyzer.scan(url)
            
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

    def analyze_technologies(self, console, scan: ScanResult) -> ScanResult:
        """
        Canonical website technology vulnerability correlation flow.
        
        Flow:
            1. Collect & normalize detected technologies.
            2. Resolve canonical package identities and evaluate eligibility.
            3. Deduplicate package identities into unique PackageInfo objects.
            4. Execute the shared canonical EnrichmentPipeline ONCE.
            5. Map findings back to each detected technology.
            6. Build structured TechnologyCorrelationResults with explicit safety states.
        """
        if not scan.website_assessment:
            return scan

        scan.website_assessment.correlation_status = CorrelationStatus.RUNNING

        # 1. Collect technologies
        technologies = self._collect_technologies(scan)

        # 2. Normalize technologies
        normalized = self._normalize_technologies(technologies)

        # 3. Resolve package identities and evaluate eligibility
        eligibilities, tech_to_identity = self._resolve_package_identities(normalized)
        scan.website_assessment.technology_eligibilities = eligibilities

        # 4. Build unique PackageInfo objects
        unique_packages, tech_to_package_key = self._build_unique_package_infos(
            normalized, eligibilities, tech_to_identity
        )

        # Render console status
        eligible_labels = []
        skipped_labels = []
        for tech in normalized:
            tech_id = getattr(tech, "signature_id", "") or tech.name.lower()
            elig = eligibilities.get(tech_id)
            ver_disp = tech.version if (tech.version and str(tech.version).strip().lower() != "unknown") else "No Version"
            if elig and elig.is_eligible:
                pkg_desc = f"{elig.ecosystem}/{elig.package_name}@{ver_disp}" if (elig.ecosystem and elig.package_name) else f"{tech.name} {ver_disp}"
                eligible_labels.append(f"✓ {tech.name} → {pkg_desc} ({elig.status.value})")
            else:
                reason = elig.reason if elig else "Unresolved"
                skipped_labels.append(f"• {tech.name} ({reason})")

        console.print("\n[bold]Analyzing detected web technologies...[/bold]\n")
        if eligible_labels:
            console.print("[bold green]Eligible for Vulnerability Correlation:[/bold green]")
            for item in eligible_labels:
                console.print(f"  {item}")
        if skipped_labels:
            console.print("\n[dim]Skipped / Non-Correlatable:[/dim]")
            for item in skipped_labels:
                console.print(f"  {item}")
        console.print()

        # 5. Correlate packages via shared EnrichmentPipeline ONCE
        all_findings, attack_paths, cpe_findings = self._correlate_packages(
            unique_packages, normalized, eligibilities, console
        )

        # 6. Map findings back to each technology
        tech_findings_map = self._map_findings_to_technologies(
            normalized, eligibilities, tech_to_package_key, all_findings, cpe_findings
        )

        # 7. Build structured TechnologyCorrelationResult for every detected technology
        correlation_results, correlated_count, failed_count = self._build_correlation_results(
            normalized, eligibilities, tech_findings_map
        )
        scan.website_assessment.technology_correlation_results = correlation_results
        scan.website_assessment.correlated_technologies = correlated_count
        scan.website_assessment.failed_technologies = failed_count

        # 8. Finalize ScanResult
        unified_findings = list(all_findings)
        for cf in cpe_findings:
            if not any(f.cve_id == cf.cve_id and f.package.name == cf.package.name for f in unified_findings):
                unified_findings.append(cf)

        unified_findings.sort(key=lambda x: x.risk_heat_score, reverse=True)

        scan.findings = unified_findings
        scan.attack_paths = attack_paths
        scan.packages_scanned = len(unique_packages)
        scan.attack_surface_score = EnrichmentPipeline.calculate_attack_surface_score(unified_findings)

        # Build target fingerprint from package/version list
        if unique_packages:
            sorted_pkg_str = "\n".join(f"{p.ecosystem}:{p.name}@{p.version}" for p in sorted(unique_packages, key=lambda p: (p.ecosystem or "", p.name or "")))
            scan.target_fingerprint = hashlib.sha256(sorted_pkg_str.encode("utf-8")).hexdigest()

        # Populate upgrade recommendations and advisory
        populate_scan_recommendations(scan)

        scan.website_assessment.correlation_status = (
            CorrelationStatus.COMPLETED if (failed_count == 0 or correlated_count > 0) else CorrelationStatus.FAILED
        )
        scan.website_assessment.correlation_completed_at = datetime.now()

        if not getattr(scan, "_reconstructing", False):
            try:
                history = history_mod.HistoryService()
                delta = history.get_posture_delta(scan)
                advisor = SecurityAdvisor()
                scan._advisor_report = advisor.analyze(scan)
                scan._delta = delta
                ReportService.create_scan_report(scan, posture_delta=delta, advisor=advisor)
            except Exception as e:
                logger.debug("History/Report generation in website service: %s", e)

        return scan

    # -----------------------------------------------------------------------
    # Modular Pipeline Helpers
    # -----------------------------------------------------------------------

    def _collect_technologies(self, scan: ScanResult) -> List[TechnologyFingerprint]:
        if not scan.website_assessment:
            return []
        return scan.website_assessment.technologies or []

    def _normalize_technologies(self, technologies: List[TechnologyFingerprint]) -> List[TechnologyFingerprint]:
        normalized = []
        for tech in technologies:
            raw_name = getattr(tech, "name", "")
            raw_version = getattr(tech, "version", None)
            if raw_version and isinstance(raw_version, str):
                v_clean = raw_version.strip().lstrip("vV")
                tech.version = v_clean if v_clean and v_clean.lower() != "unknown" else None
            normalized.append(tech)
        return normalized

    def _resolve_package_identities(
        self, technologies: List[TechnologyFingerprint]
    ) -> Tuple[Dict[str, CorrelationEligibility], Dict[str, Any]]:
        eligibilities = evaluate_all_eligibilities(technologies)
        tech_to_identity: Dict[str, Any] = {}
        for tech in technologies:
            tech_id = getattr(tech, "signature_id", "") or tech.name.lower()
            elig = eligibilities.get(tech_id)
            if elig and elig.package_identity:
                tech_to_identity[tech.name] = elig.package_identity
        return eligibilities, tech_to_identity

    def _build_unique_package_infos(
        self,
        technologies: List[TechnologyFingerprint],
        eligibilities: Dict[str, CorrelationEligibility],
        tech_to_identity: Dict[str, Any]
    ) -> Tuple[List[PackageInfo], Dict[str, Tuple[str, str, str]]]:
        """
        Deduplicate resolved technologies into unique PackageInfo instances.
        Returns:
            (unique_package_list, tech_name_to_package_key_mapping)
        """
        unique_map: Dict[Tuple[str, str, str], PackageInfo] = {}
        tech_to_package_key: Dict[str, Tuple[str, str, str]] = {}

        for tech in technologies:
            tech_id = getattr(tech, "signature_id", "") or tech.name.lower()
            elig = eligibilities.get(tech_id)
            if not elig or not elig.is_eligible:
                continue

            eco = elig.ecosystem
            pkg_name = elig.package_name
            ver = tech.version

            if eco and pkg_name and ver:
                pkg_key = (eco.lower().strip(), pkg_name.lower().strip(), str(ver).strip())
                if pkg_key not in unique_map:
                    unique_map[pkg_key] = PackageInfo(
                        name=pkg_name,
                        version=str(ver).strip(),
                        ecosystem=eco,
                        dependency_type="DIRECT"
                    )
                tech_to_package_key[tech.name] = pkg_key

        return list(unique_map.values()), tech_to_package_key

    def _correlate_packages(
        self,
        unique_packages: List[PackageInfo],
        technologies: List[TechnologyFingerprint],
        eligibilities: Dict[str, CorrelationEligibility],
        console: Any
    ) -> Tuple[List[VulnerabilityFinding], List[Any], List[VulnerabilityFinding]]:
        """
        Executes shared EnrichmentPipeline ONCE for all unique packages and
        correlates CPE-only technologies where applicable.
        """
        all_findings: List[VulnerabilityFinding] = []
        attack_paths: List[Any] = []
        cpe_findings: List[VulnerabilityFinding] = []

        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            # 1. Execute Shared EnrichmentPipeline for canonical packages
            if unique_packages:
                task_scan = progress.add_task(
                    f"[yellow]Correlating vulnerabilities via shared pipeline ({len(unique_packages)} unique packages)...[/yellow]",
                    total=None
                )
                pipeline = EnrichmentPipeline()
                enrich_result = pipeline.run(unique_packages, progress=progress)
                all_findings = enrich_result.findings
                attack_paths = enrich_result.attack_paths
                progress.update(
                    task_scan,
                    completed=1,
                    description=f"[green]Package Vulnerability Pipeline[/green] found {len(all_findings)} vulnerabilities"
                )

            # 2. Correlate CPE-only technologies
            cpe_only_techs = []
            for tech in technologies:
                tech_id = getattr(tech, "signature_id", "") or tech.name.lower()
                elig = eligibilities.get(tech_id)
                if elig and elig.is_eligible and not elig.package_name and (elig.cpe_vendor and elig.cpe_product):
                    cpe_only_techs.append((tech, elig))

            if cpe_only_techs:
                task_cpe = progress.add_task("[yellow]Matching CPE-only technologies (NVD)...[/yellow]", total=None)
                try:
                    from pulse.enrichment.nvd.correlator import NVDCorrelationEngine
                    from pulse.correlation.models import CorrelationResult, CPECandidate, ResolverMatchType
                    engine = NVDCorrelationEngine()
                    cpe_results = []
                    for tech, elig in cpe_only_techs:
                        ver_str = tech.version or "*"
                        cpe_str = f"cpe:2.3:a:{elig.cpe_vendor}:{elig.cpe_product}:{ver_str}:*:*:*:*:*:*:*"
                        candidate = CPECandidate(
                            cpe_template=f"cpe:2.3:a:{elig.cpe_vendor}:{elig.cpe_product}:*:*:*:*:*:*:*",
                            detected_version=tech.version,
                            resolved_cpe=cpe_str,
                            confidence=tech.confidence,
                            source="capability",
                            vendor=elig.cpe_vendor,
                            product=elig.cpe_product,
                            exact_version_match=bool(tech.version),
                            match_type=ResolverMatchType.EXACT
                        )
                        cpe_results.append(CorrelationResult(
                            technology=tech.name,
                            inventory_technology_key=tech.name.lower(),
                            candidates=[candidate],
                            selected_candidate=candidate,
                            resolution_confidence=tech.confidence
                        ))

                    correlated_cpe_vulns, _ = engine.correlate(cpe_results)
                    for cv in correlated_cpe_vulns:
                        dummy_pkg = PackageInfo(name=cv.technology_name, version=cv.version or "Unknown", ecosystem="CPE")
                        cpe_findings.append(VulnerabilityFinding(
                            package=dummy_pkg,
                            cve_id=cv.cve_id,
                            cvss_score=cv.cvss_v3_score or 0.0,
                            cvss_severity=cv.severity or "UNKNOWN",
                            description=cv.description or "",
                            source="NVD",
                            published_date=cv.published_date.strftime("%Y-%m-%d") if cv.published_date else None,
                            nvd_url=cv.nvd_url or "",
                            cwe=cv.cwe,
                            source_type=FindingSourceType.WEBSITE,
                            source_asset=cv.technology_name
                        ))
                    progress.update(task_cpe, completed=1, description=f"[green]CPE Correlation[/green] found {len(cpe_findings)} vulnerabilities")
                except Exception as e:
                    logger.debug("CPE correlation failed: %s", e)
                    progress.update(task_cpe, completed=1, description="[yellow]CPE Correlation completed[/yellow]")

        # Tag all findings with FindingSourceType.WEBSITE and evidence adjustments
        for finding in all_findings:
            finding.source_type = FindingSourceType.WEBSITE
            matched_tech = next(
                (t for t in technologies if (
                    t.name.lower() == finding.package.name.lower() or
                    (eligibilities.get(getattr(t, "signature_id", "") or t.name.lower()) and
                     eligibilities[getattr(t, "signature_id", "") or t.name.lower()].package_name and
                     eligibilities[getattr(t, "signature_id", "") or t.name.lower()].package_name.lower() == finding.package.name.lower())
                )),
                None
            )
            if matched_tech:
                finding.source_asset = matched_tech.name
                mult = get_confidence_multiplier(matched_tech.evidence)
                finding.detection_confidence = matched_tech.confidence
                finding.source_evidence = [f"{ev.method.value if hasattr(ev.method, 'value') else ev.method}: {ev.source}" for ev in matched_tech.evidence]
                finding.risk_heat_score = calculate_adjusted_risk(finding.risk_heat_score, mult)

        return all_findings, attack_paths, cpe_findings

    def _map_findings_to_technologies(
        self,
        technologies: List[TechnologyFingerprint],
        eligibilities: Dict[str, CorrelationEligibility],
        tech_to_package_key: Dict[str, Tuple[str, str, str]],
        all_findings: List[VulnerabilityFinding],
        cpe_findings: List[VulnerabilityFinding]
    ) -> Dict[str, List[VulnerabilityFinding]]:
        """Maps unified findings back to their respective technology fingerprints."""
        tech_findings_map: Dict[str, List[VulnerabilityFinding]] = {t.name: [] for t in technologies}

        for tech in technologies:
            pkg_key = tech_to_package_key.get(tech.name)
            if pkg_key:
                eco_key, name_key, ver_key = pkg_key
                for f in all_findings:
                    f_eco = (f.package.ecosystem or "").lower().strip()
                    f_name = (f.package.name or "").lower().strip()
                    f_ver = str(f.package.version or "").strip()
                    if f_name == name_key and (f_ver == ver_key or not ver_key):
                        if f not in tech_findings_map[tech.name]:
                            tech_findings_map[tech.name].append(f)

            # Also check CPE findings
            for cf in cpe_findings:
                if cf.source_asset and cf.source_asset.lower() == tech.name.lower():
                    if cf not in tech_findings_map[tech.name]:
                        tech_findings_map[tech.name].append(cf)

        return tech_findings_map

    def _build_correlation_results(
        self,
        technologies: List[TechnologyFingerprint],
        eligibilities: Dict[str, CorrelationEligibility],
        tech_findings_map: Dict[str, List[VulnerabilityFinding]]
    ) -> Tuple[Dict[str, TechnologyCorrelationResult], int, int]:
        """
        Builds explicit structured TechnologyCorrelationResult objects ensuring
        critical security state semantics.
        """
        correlation_results: Dict[str, TechnologyCorrelationResult] = {}
        correlated_count = 0
        failed_count = 0

        for tech in technologies:
            tech_id = getattr(tech, "signature_id", "") or tech.name.lower()
            elig = eligibilities.get(tech_id)
            findings = tech_findings_map.get(tech.name, [])

            if findings:
                status = "VULNERABILITIES_FOUND"
                reason = f"{len(findings)} vulnerabilities detected"
                correlated_count += 1
            elif elig and elig.is_eligible and elig.version_available:
                status = "NO_KNOWN_VULNERABILITIES"
                reason = "No known vulnerabilities found in verified package identity"
                correlated_count += 1
            elif elig and elig.status == CorrelationEligibilityStatus.VERSION_REQUIRED:
                status = "VERSION_REQUIRED"
                reason = "Version required for vulnerability correlation"
            elif elig and elig.status == CorrelationEligibilityStatus.DETECTION_ONLY:
                status = "DETECTION_ONLY"
                reason = elig.reason or "Detection-only technology / infrastructure"
            else:
                status = "CORRELATION_UNAVAILABLE"
                reason = (elig.reason if elig else "") or "Package identity could not be resolved"
                failed_count += 1

            pkg_name = elig.package_name if elig else None
            eco = elig.ecosystem if elig else None
            reg = getattr(elig.package_identity, "registry", None) if elig else None

            correlation_results[tech.name] = TechnologyCorrelationResult(
                technology_name=tech.name,
                detected_version=tech.version,
                package_name=pkg_name,
                ecosystem=eco,
                registry=reg,
                correlation_status=status,
                correlation_reason=reason,
                vulnerabilities=findings
            )

        return correlation_results, correlated_count, failed_count
