from datetime import datetime, timedelta
from typing import List, Optional
from pulse import __version__
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.reporting.context import ReportContext
from pulse.reporting.models import (
    ReportModel, Severity, ExecutiveSummaryModel, RiskSummaryModel,
    ReportFindingModel, WebsiteTechnologyModel, PackageInventoryItem,
    RemediationItem, BaseSection, WebsiteAssessmentSection,
    DependencyInventorySection, RemediationSection, ReportMetadata
)

class ReportBuilder:
    """Pure converter that transforms a ReportContext (wrapping a ScanResult) into a canonical ReportModel."""

    @staticmethod
    def build(context: ReportContext) -> ReportModel:
        scan: ScanResult = context.scan_result
        
        # 1. Timestamps & Duration
        finished_at = context.generated_at
        duration_sec = scan.scan_duration_seconds or 0.0
        started_at = scan.timestamp or (finished_at - timedelta(seconds=duration_sec))
        duration = timedelta(seconds=duration_sec)

        # 2. Executive Summary
        exec_summary = ExecutiveSummaryModel(
            target_id=scan.target_id or "global",
            target_type=scan.target_type or "package",
            scan_started=started_at,
            scan_finished=finished_at,
            duration=duration,
            packages_scanned=scan.packages_scanned,
            vulnerable_count=scan.vulnerable_packages_count,
            attack_surface_score=scan.attack_surface_score
        )

        # 3. Severity & Risk Summary
        sev_counts = {sev: 0 for sev in Severity}
        finding_models: List[ReportFindingModel] = []
        vulnerable_pkg_set = set()

        for f in scan.findings:
            sev = Severity.from_str(f.cvss_severity)
            sev_counts[sev] += 1
            if f.package:
                vulnerable_pkg_set.add((f.package.name, f.package.version))

            techniques = []
            if hasattr(f, "attack_techniques") and f.attack_techniques:
                for tech in f.attack_techniques:
                    tid = getattr(tech, "technique_id", None) or (tech.get("id") if isinstance(tech, dict) else str(tech))
                    tname = getattr(tech, "technique_name", None) or (tech.get("name") if isinstance(tech, dict) else "Technique name unavailable") or "Technique name unavailable"
                    ttactic = getattr(tech, "tactic", None) or (tech.get("tactic") if isinstance(tech, dict) else None)
                    techniques.append({
                        "id": tid,
                        "name": tname,
                        "tactic": ttactic
                    })

            rem_cmd = ReportBuilder._generate_remediation_command(f, scan)
            rec = scan.get_recommendation(f.package.name, f.package.ecosystem) if f.package else None
            rec_fix_ver = rec.recommended_version if rec else f.fix_version

            pkg_name = f.package.name if f.package else "Unknown"
            pkg_version = f.package.version if f.package else "Unknown"
            ecosystem = f.package.ecosystem if f.package else "Unknown"

            finding_models.append(
                ReportFindingModel(
                    cve_id=f.cve_id or "UNKNOWN",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    ecosystem=ecosystem,
                    severity=sev,
                    cvss_score=f.cvss_score or 0.0,
                    epss_percent=f.epss_percent or "0%",
                    kev_match=bool(f.kev_match),
                    risk_heat_score=f.risk_heat_score or 0,
                    description=f.description or f"Vulnerability {f.cve_id}",
                    fix_version=rec_fix_ver or f.fix_version,
                    remediation_command=rem_cmd,
                    attack_techniques=techniques,
                    nvd_url=f.nvd_url
                )
            )

        # Delta metrics
        prev_score = None
        score_delta = None
        if context.posture_delta:
            prev_score = context.posture_delta.previous_score
            score_delta = context.posture_delta.risk_score_change

        # Direct vs Transitive
        direct_cnt = 0
        transitive_cnt = 0
        if scan.supply_chain_metrics:
            direct_cnt = scan.supply_chain_metrics.direct_count
            transitive_cnt = scan.supply_chain_metrics.transitive_count
        else:
            direct_cnt = scan.packages_scanned

        risk_summary = RiskSummaryModel(
            critical_count=sev_counts[Severity.CRITICAL],
            high_count=sev_counts[Severity.HIGH],
            medium_count=sev_counts[Severity.MEDIUM],
            low_count=sev_counts[Severity.LOW],
            informational_count=sev_counts[Severity.INFORMATIONAL],
            kev_matches_count=scan.kev_matches_count,
            average_risk_score=scan.average_risk_score,
            direct_packages_count=direct_cnt,
            transitive_packages_count=transitive_cnt,
            previous_score=prev_score,
            score_delta=score_delta
        )

        # 4. Sections
        sections: List[BaseSection] = []

        # Section: Website Assessment (if applicable)
        if scan.website_assessment:
            from pulse.website.capability import CorrelationEligibilityStatus, evaluate_correlation_eligibility
            eligibilities = getattr(scan.website_assessment, 'technology_eligibilities', {})
            
            tech_models = []
            for t in scan.website_assessment.technologies:
                vuln_cnt = sum(1 for f in finding_models if f.package_name == t.name)
                
                # Use stored eligibility (Single Source of Truth)
                tech_id = getattr(t, "signature_id", "") or t.name.lower()
                elig = eligibilities.get(tech_id)
                if not elig:
                    elig = evaluate_correlation_eligibility(t)
                is_correlated = elig.status in (
                    CorrelationEligibilityStatus.CORRELATABLE,
                    CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
                )
                
                tech_models.append(
                    WebsiteTechnologyModel(
                        name=t.name,
                        version=t.version,
                        category=t.category or "Technology",
                        confidence=t.confidence,
                        correlated=is_correlated,
                        vulnerability_count=vuln_cnt,
                        correlation_status=elig.status.value,
                        intelligence_sources=elig.intelligence_sources,
                    )
                )
            sections.append(
                WebsiteAssessmentSection(
                    name="Website Assessment",
                    url=scan.website_assessment.url,
                    correlation_status=scan.website_assessment.correlation_status.value if hasattr(scan.website_assessment.correlation_status, "value") else str(scan.website_assessment.correlation_status),
                    technologies=tech_models
                )
            )

        # Section: Dependency Inventory
        inventory_items = []
        seen_packages = set()
        for f in scan.findings:
            if f.package and (f.package.name, f.package.version) not in seen_packages:
                seen_packages.add((f.package.name, f.package.version))
                inventory_items.append(
                    PackageInventoryItem(
                        name=f.package.name,
                        version=f.package.version,
                        ecosystem=f.package.ecosystem,
                        direct=(f.package.dependency_type == "DIRECT"),
                        vulnerable=True
                    )
                )

        sections.append(
            DependencyInventorySection(
                name="Dependency Inventory",
                total_packages=scan.packages_scanned,
                items=inventory_items
            )
        )

        # Section: Remediation
        remediation_items = []
        remediation_map = {}
        for fm in finding_models:
            if fm.fix_version and fm.remediation_command:
                key = (fm.package_name, fm.remediation_command)
                if key not in remediation_map:
                    prio = 1 if fm.severity == Severity.CRITICAL else (2 if fm.severity == Severity.HIGH else 3)
                    remediation_map[key] = RemediationItem(
                        title=f"Upgrade {fm.package_name} to {fm.fix_version}",
                        command=fm.remediation_command,
                        priority=prio,
                        affected_packages=[fm.package_name]
                    )
        remediation_items = sorted(remediation_map.values(), key=lambda r: r.priority)
        sections.append(
            RemediationSection(
                name="Remediation Plan",
                items=remediation_items
            )
        )

        # 5. Metadata
        metadata = ReportMetadata(
            pulse_version=scan.tool_version or __version__,
            report_schema_version="2.0",
            template_version="1.0",
            generated_at=context.generated_at,
            database_versions={
                "osv": "Active",
                "nvd": "Active",
                "epss": "Active",
                "kev": "Active"
            }
        )

        return ReportModel(
            executive_summary=exec_summary,
            risk_summary=risk_summary,
            findings=finding_models,
            sections=sections,
            metadata=metadata
        )

    @staticmethod
    def _generate_remediation_command(finding: VulnerabilityFinding, scan: Optional[ScanResult] = None) -> Optional[str]:
        if not finding.package:
            return None
        if scan:
            rec = scan.get_recommendation(finding.package.name, finding.package.ecosystem)
            if rec and rec.upgrade_command:
                return rec.upgrade_command
            if rec and rec.recommended_version:
                from pulse.remediation.command_generator import generate_upgrade_command
                return generate_upgrade_command(finding.package.name, finding.package.ecosystem, rec.recommended_version)
        if not finding.fix_version:
            return None
        from pulse.remediation.command_generator import generate_upgrade_command
        return generate_upgrade_command(finding.package.name, finding.package.ecosystem, finding.fix_version)
