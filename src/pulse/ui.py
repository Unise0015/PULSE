from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Tuple, Any
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich.tree import Tree
from rich import box
import textwrap

from pulse.domain.models import ScanResult, VulnerabilityFinding, PostureDelta, FindingSourceType

if TYPE_CHECKING:
    from pulse.security_advisor import SecurityAdvisorReport, PackageAction, PackageHealth


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_severity_color(severity: str) -> str:
    sev = severity.upper()
    if sev == "CRITICAL":
        return "bold red"
    elif sev == "HIGH":
        return "bold dark_orange"
    elif sev == "MEDIUM":
        return "bold yellow"
    elif sev == "LOW":
        return "bold green"
    elif sev == "INFORMATIONAL":
        return "bold blue"
    return "white"


def format_kev(finding: VulnerabilityFinding) -> str:
    if finding.kev_match:
        return "[bold red]ACTIVE EXPLOIT[/bold red]"
    return "[dim]No[/dim]"

def clean_display_text(value: str) -> str:
    """Normalize text before displaying it in the CLI presentation layer.
    
    Safely normalizes raw literal escape sequences like '\\n', '\\r\\n' to real newlines
    without modifying serialized JSON, stored DB items, or API payloads.
    """
    if not value or not isinstance(value, str):
        return ""
    return str(value).replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n")



def get_recommended_command(pkg_name: str, ecosystem: str) -> str:
    """Returns the full upgrade-to-latest command."""
    eco = ecosystem.lower()
    if "python" in eco or "pypi" in eco:
        return f"pip install --upgrade {pkg_name}"
    elif "npm" in eco or "node" in eco:
        return f"npm update {pkg_name}"
    return f"Upgrade {pkg_name} to latest"


# ── Panels & Tables ────────────────────────────────────────────────────────────

def render_provider_statistics(console, scan: ScanResult):
    """Renders Provider Statistics table on demand."""
    from pulse.core.provider_health import provider_tracker, ProviderStatus

    health_map = provider_tracker.get_all_health()
    table = Table(title="[bold cyan]Provider Statistics[/bold cyan]", box=box.ROUNDED, expand=True)
    table.add_column("Provider", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Records", justify="center")
    table.add_column("Cache Hits/Misses", justify="center")
    table.add_column("Requests", justify="center")
    table.add_column("Time", justify="right")

    total_time_ms = 0.0
    total_requests = 0
    total_hits = 0
    total_misses = 0

    for p_name, p_health in health_map.items():
        status_color = "bold green" if p_health.status in (ProviderStatus.HEALTHY, ProviderStatus.CACHE_ONLY) else ("bold yellow" if p_health.status == ProviderStatus.PARTIAL else "bold red")
        status_str = f"[{status_color}]{p_health.status.value}[/{status_color}]"
        records_str = f"{p_health.records_enriched}/{p_health.records_requested}" if p_health.records_requested > 0 else f"{len(scan.findings)} enriched"
        cache_str = f"{p_health.cache_hits}H / {p_health.cache_misses}M"
        time_str = f"{int(p_health.duration_ms)} ms"
        table.add_row(p_name, status_str, records_str, cache_str, str(p_health.network_requests), time_str)

        total_time_ms += p_health.duration_ms
        total_requests += p_health.network_requests
        total_hits += p_health.cache_hits
        total_misses += p_health.cache_misses

    cache_total = total_hits + total_misses
    cache_eff = f"{(total_hits / cache_total * 100):.1f}%" if cache_total > 0 else "N/A"
    table.add_section()
    table.add_row("[bold]Total / Efficiency[/bold]", "", "", f"Efficiency: {cache_eff}", f"Reqs: {total_requests}", f"[bold cyan]{(total_time_ms / 1000.0):.2f} s[/bold cyan]")
    console.print(table)


def render_scan_integrity(console, scan: ScanResult):
    """Renders Scan Integrity rating panel on demand."""
    from pulse.core.provider_health import provider_tracker
    from pulse.core.enrichment_validator import EnrichmentConsistencyValidator, ScanIntegrity

    health_map = provider_tracker.get_all_health()
    summary, _ = EnrichmentConsistencyValidator.validate_scan_findings(scan)
    integrity, reasons = EnrichmentConsistencyValidator.calculate_scan_integrity(health_map, summary, len(scan.findings))

    integ_color = "bold green" if integrity == ScanIntegrity.HIGH else ("bold yellow" if integrity == ScanIntegrity.MEDIUM else "bold red")
    if reasons:
        reasons_list = "\n".join([f" • {r}" for r in reasons])
        reason_text = f"[bold]Contributing Factors:[/bold]\n{reasons_list}"
    else:
        reason_text = "[dim]All intelligence invariants deterministically validated cleanly[/dim]"

    console.print(Panel(
        f"[{integ_color}]Scan Integrity: {integrity.value}[/{integ_color}]\n\n{reason_text}",
        title="[bold white]Intelligence Confidence & Scan Integrity[/bold white]",
        box=box.SQUARE,
        expand=False
    ))


def render_validation_summary(console, scan: ScanResult):
    """Renders Data Validation Summary panel on demand."""
    from pulse.core.provider_health import provider_tracker
    from pulse.core.enrichment_validator import EnrichmentConsistencyValidator

    health_map = provider_tracker.get_all_health()
    summary, _ = EnrichmentConsistencyValidator.validate_scan_findings(scan)

    val_lines = [
        f"[green]✓[/green] Valid CVEs: {summary.valid_cves_count}",
        f"[green]✓[/green] Valid CVSS Scores: {summary.valid_cvss_count}"
    ]
    if summary.missing_cwe_count > 0:
        val_lines.append(f"[yellow]⚠[/yellow] Missing CWE Mappings: {summary.missing_cwe_count}")
    else:
        val_lines.append("[green]✓[/green] All CWE Mappings Validated")

    if summary.missing_description_count > 0:
        val_lines.append(f"[yellow]⚠[/yellow] Missing Vulnerability Descriptions: {summary.missing_description_count}")

    if summary.duplicate_count > 0:
        val_lines.append(f"[yellow]⚠[/yellow] Duplicate Findings Filtered: {summary.duplicate_count}")
    else:
        val_lines.append("[green]✓[/green] No Duplicate Findings Detected")

    if summary.validation_failures_count > 0:
        val_lines.append(f"[bold red]✖ Record Validation Failures: {summary.validation_failures_count}[/bold red]")

    console.print(Panel(
        "\n".join(val_lines),
        title="[bold white]Validation Summary[/bold white]",
        box=box.ROUNDED,
        expand=False
    ))


def render_performance_summary(console, scan: ScanResult):
    """Renders Performance & Timing breakdown panel on demand."""
    from pulse.core.provider_health import provider_tracker

    health_map = provider_tracker.get_all_health()
    total_time_s = getattr(scan, "scan_duration_seconds", 0.0) or 0.0
    total_reqs = sum(p.network_requests for p in health_map.values())
    total_hits = sum(p.cache_hits for p in health_map.values())
    total_misses = sum(p.cache_misses for p in health_map.values())
    cache_total = total_hits + total_misses
    cache_eff = f"{(total_hits / cache_total * 100):.1f}%" if cache_total > 0 else "N/A"

    text = Text()
    text.append(f"{'Total Scan Duration:':<28} {total_time_s:.2f} s\n", style="bold cyan")
    text.append(f"{'Network Requests:':<28} {total_reqs}\n")
    text.append(f"{'Cache Efficiency:':<28} {cache_eff}\n")
    text.append("\nProvider Durations:\n", style="bold")

    for p_name, p_health in health_map.items():
        text.append(f"  - {p_name:<24} {int(p_health.duration_ms)} ms\n")

    console.print(Panel(text, title="[bold white]Performance Metrics[/bold white]", box=box.ROUNDED, expand=False))


def print_provider_observability(console, scan: ScanResult):
    """Renders Provider Statistics, Validation Summary, and Scan Integrity card."""
    render_provider_statistics(console, scan)
    render_scan_integrity(console, scan)
    render_validation_summary(console, scan)


def print_security_summary(console, scan: ScanResult, compact: bool = False):
    if not scan.findings and scan.vulnerable_packages_count == 0:
        summary_text = Text()
        summary_text.append(f"{'Dependencies Scanned:':<28} {scan.packages_scanned}\n", style="bold")
        summary_text.append(f"[bold green]No vulnerabilities detected[/bold green]")
        console.print(Panel(
            summary_text,
            box=box.SQUARE,
            expand=False,
            title="[bold green]Security Summary[/bold green]"
        ))
        return

    text = Text()
    text.append(f"{'Dependencies:':<28} {scan.packages_scanned}\n", style="bold")
    text.append(f"{'Vulnerabilities:':<28} {len(scan.findings)}\n", style="bold")
    text.append(f"{'High/Critical:':<28} {scan.critical_count + scan.high_count}\n", style="bold red")
    text.append(f"{'Risk Score:':<28} {scan.attack_surface_score}\n", style="bold magenta")

    if not compact and getattr(scan, "detected_ecosystems", None) and len(scan.detected_ecosystems) > 1:
        text.append("\nEcosystems:\n", style="bold cyan")
        for eco in scan.detected_ecosystems:
            text.append(f"  - {eco}\n")

    console.print(Panel(text, title="[bold]Security Summary[/bold]", box=box.ROUNDED, expand=False))

def print_priority_summary(console, scan: ScanResult):
    metrics = getattr(scan, "supply_chain_metrics", None)
    if not metrics:
        return

    text = Text()
    vd_style = "bold red" if metrics.vulnerable_direct > 0 else "default"
    text.append(f"{'Vulnerable Direct:':<28} {metrics.vulnerable_direct}\n", style=vd_style)
    
    vt_style = "bold yellow" if metrics.vulnerable_transitive > 0 else "default"
    text.append(f"{'Vulnerable Transitive:':<28} {metrics.vulnerable_transitive}\n", style=vt_style)

    console.print(Panel(text, title="[bold]Top Priorities[/bold]", box=box.ROUNDED, expand=False))

def print_threat_summary(console, scan: ScanResult):
    text = Text()
    has_data = False

    if scan.kev_matches > 0:
        text.append(f"{'KEV Matches:':<28} {scan.kev_matches} (Active Exploits!)\n\n", style="bold red")
        has_data = True

    techniques = {}
    technique_names = {}
    tactics = {}
    for f in scan.findings:
        seen_tids = set()
        seen_tacs = set()
        for t in getattr(f, "attack_techniques", []):
            if t.technique_id not in seen_tids:
                techniques[t.technique_id] = techniques.get(t.technique_id, 0) + 1
                if getattr(t, "technique_name", None):
                    technique_names[t.technique_id] = t.technique_name
                seen_tids.add(t.technique_id)
            if t.tactic not in seen_tacs:
                tactics[t.tactic] = tactics.get(t.tactic, 0) + 1
                seen_tacs.add(t.tactic)
                
    if techniques:
        has_data = True
        text.append("MITRE ATT&CK:\n", style="bold cyan")
        text.append("  Top Techniques:\n", style="bold")
        for tid, count in sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:3]:
            name = technique_names.get(tid, "Technique name unavailable")
            text.append(f"    {tid} — {name} ({count})\n")
        text.append("  Top Tactics:\n", style="bold")
        for tac, count in sorted(tactics.items(), key=lambda x: x[1], reverse=True)[:3]:
            text.append(f"    {tac:<26} ({count})\n")

    if has_data:
        console.print(Panel(text, title="[bold]Threat Intelligence[/bold]", box=box.ROUNDED, expand=False))

def print_supply_chain_summary(console, scan: ScanResult):
    metrics = getattr(scan, "supply_chain_metrics", None)
    if not metrics:
        return

    text = Text()
    text.append(f"{'Direct Dependencies:':<28} {metrics.direct_count}\n")
    text.append(f"{'Transitive Dependencies:':<28} {metrics.transitive_count}\n")
    text.append(f"{'Max Dependency Depth:':<28} {metrics.max_depth}\n")

    console.print(Panel(text, title="[bold]Supply Chain Analysis[/bold]", box=box.ROUNDED, expand=False))

def print_attack_paths(console, scan: ScanResult):
    if not getattr(scan, "attack_paths", []):
        return

    top_score = scan.attack_paths[0].exposure_score
    kev_backed = sum(1 for p in scan.attack_paths if p.kev_match)
    
    text = Text()
    text.append(f"{'Top Exposure Score:':<28} {top_score}\n", style="bold red")
    text.append(f"{'Attack Paths Identified:':<28} {len(scan.attack_paths)}\n")
    text.append(f"{'KEV-Backed Paths:':<28} {kev_backed}\n")
    
    console.print(Panel(text, title="[bold]Exposure Metrics[/bold]", box=box.ROUNDED, expand=False))

def print_trend_summary(console, delta: Optional[PostureDelta]):
    text = Text()
    if not delta:
        text.append("First scan for this target\n", style="italic dim")
        console.print(Panel(text, title="[bold]Trend Analysis[/bold]", box=box.ROUNDED, expand=False))
        return

    prev_score = getattr(delta, "previous_score", 0)
    current_score = getattr(delta, "current_score", 0)
    risk_score_change = getattr(delta, "risk_score_change", 0)
    new_cves = getattr(delta, "new_cves", []) or []
    remediated_cves = getattr(delta, "remediated_cves", []) or []
    kev_change_count = getattr(delta, "kev_change_count", 0)
    critical_count_change = getattr(delta, "critical_count_change", 0)
    highest_new_risk = getattr(delta, "highest_new_risk", None)
    highest_resolved_cve = getattr(delta, "highest_resolved_cve", None)
    highest_resolved_risk_score = getattr(delta, "highest_resolved_risk_score", None)

    new_criticals = sum(1 for f in new_cves if getattr(f, "cvss_severity", "").upper() == "CRITICAL")

    text.append(f"{'Previous Score:':<28} {prev_score}\n")
    
    change_sign = "+" if risk_score_change > 0 else ""
    change_style = "bold red" if risk_score_change > 0 else "bold green" if risk_score_change < 0 else "bold white"
    text.append(f"{'Change:':<28} {change_sign}{risk_score_change}\n", style=change_style)

    if new_cves:
        text.append(f"{'New Vulnerabilities:':<28} {len(new_cves)}\n", style="bold red" if new_criticals > 0 else "yellow")

    if new_criticals > 0:
        text.append(f"{'New Critical Findings:':<28} {new_criticals}\n", style="bold red")

    if remediated_cves:
        text.append(f"{'Remediated Vulnerabilities:':<28} {len(remediated_cves)}\n", style="bold green")

    if kev_change_count != 0:
        kev_sign = "+" if kev_change_count > 0 else ""
        kev_style = "bold red" if kev_change_count > 0 else "bold green"
        text.append(f"{'KEV Match Change:':<28} {kev_sign}{kev_change_count}\n", style=kev_style)

    if highest_new_risk:
        cve_id = getattr(highest_new_risk, "cve_id", "Unknown")
        risk = getattr(highest_new_risk, "risk_heat_score", 0)
        text.append(f"{'Highest New Risk:':<28} {cve_id} (Heat: {risk})\n", style="bold red")

    if highest_resolved_cve:
        score_str = f" (Heat: {highest_resolved_risk_score})" if highest_resolved_risk_score is not None else ""
        text.append(f"{'Highest Remediated Risk:':<28} {highest_resolved_cve}{score_str}\n", style="bold green")

    trend_str = "Stable"
    if risk_score_change > 5 or new_criticals > 0 or critical_count_change > 0:
        trend_str = "Degraded"
    elif risk_score_change < -5 or (len(remediated_cves) > 0 and len(new_cves) == 0):
        trend_str = "Improved"

    trend_style = "bold red" if trend_str == "Degraded" else "bold green" if trend_str == "Improved" else "bold yellow"
    text.append(f"{'Trend:':<28} {trend_str}\n", style=trend_style)

    console.print(Panel(text, title="[bold]Trend Analysis[/bold]", box=box.ROUNDED, expand=False))


def print_highest_risk_finding(console, finding: VulnerabilityFinding, scan: Optional[ScanResult] = None):
    from pulse.ui_helpers.findings import (
        get_severity_color,
        build_finding_context,
        build_vulnerability_summary,
        build_attack_path,
        build_upgrade_analysis
    )

    pkg = finding.package
    rec = None
    if scan:
        rec = scan.get_recommendation(pkg.name, pkg.ecosystem)
    if not rec:
        from pulse.version_intelligence import analyze_upgrade_recommendation
        rec = analyze_upgrade_recommendation(
            pkg_name=pkg.name,
            ecosystem=pkg.ecosystem,
            current_version=pkg.version,
            findings=[finding],
            version_metadata=pkg.version_metadata,
            verify_candidate=True
        )

    finding.normalize_severity()
    is_info = (finding.cvss_severity == "INFORMATIONAL")
    sev_display = finding.cvss_severity
    sev_color = get_severity_color(finding.cvss_severity)
    
    panel_title = "[bold blue]Informational Finding[/bold blue]" if is_info else "[bold red]Highest Risk Finding & Upgrade Analysis[/bold red]"
    border_style = "blue" if is_info else "red"

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="bold cyan", justify="right", min_width=24)
    table.add_column("Value")

    build_finding_context(table, pkg, finding, rec, sev_color, sev_display)
    build_vulnerability_summary(table, finding)
    build_attack_path(table, finding)
    build_upgrade_analysis(table, pkg, rec)

    console.print(Panel(
        table,
        title=panel_title,
        border_style=border_style,
        box=box.SQUARE,
        expand=False
    ))

def print_remediation_table(console, scan: ScanResult):
    if not scan.findings:
        return

    from pulse.state import AppState
    from pulse.remediation import recommend_upgrade

    pkg_map: Dict[str, List[VulnerabilityFinding]] = {}
    for f in scan.findings:
        key = scan.make_package_key(f.package.ecosystem, f.package.name)
        if key not in pkg_map:
            pkg_map[key] = []
        pkg_map[key].append(f)

    recommendations = []
    for key, f_list in pkg_map.items():
        sample_pkg = f_list[0].package
        rec = scan.get_recommendation(sample_pkg.name, sample_pkg.ecosystem)
        if not rec:
            rec = recommend_upgrade(
                package=sample_pkg.name,
                ecosystem=sample_pkg.ecosystem,
                current_version=sample_pkg.version,
                findings=f_list,
                version_metadata=sample_pkg.version_metadata
            )
            scan.upgrade_recommendations[key] = rec
        recommendations.append(rec)

    has_diff_latest = any(r.latest_stable and r.latest_stable != r.recommended_version for r in recommendations)

    version_table = Table(
        title="[bold cyan]Package Upgrade Dashboard[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        show_lines=True,
    )
    version_table.add_column("Package",                  style="bold white",  min_width=14)
    version_table.add_column("Current",                  justify="center",    style="dim", min_width=10)
    version_table.add_column("Recommended",              justify="center",    style="bold yellow", min_width=16)
    version_table.add_column("Latest Stable",            justify="center",    style="green", min_width=12)
    if AppState.DEBUG_MODE:
        version_table.add_column("Lowest Candidate Fix", justify="center",    style="bold green", min_width=16)
    version_table.add_column("Verification",             justify="center",    min_width=12)
    version_table.add_column("Migration Risk",           justify="center",    min_width=12)
    version_table.add_column("Security Gap",             justify="center",    style="bold red", min_width=10)

    for key, f_list in pkg_map.items():
        rec = [r for r in recommendations if scan.make_package_key(r.ecosystem, r.package_name) == key][0]

        risk_val = rec.migration_risk.value if hasattr(rec.migration_risk, "value") else str(rec.migration_risk)
        risk_color = "bold green" if risk_val == "LOW" else ("bold yellow" if risk_val == "MEDIUM" else "bold red")

        conf_val = rec.confidence.value if hasattr(rec.confidence, "value") else str(rec.confidence)
        conf_color = "bold green" if conf_val == "HIGH" else ("bold yellow" if conf_val == "MEDIUM" else "dim")

        rec_ver_str = rec.recommended_version or "N/A"
        if rec.verified_safe:
            rec_cell = f"[bold green]{rec_ver_str}[/bold green] ✅ Verified"
        else:
            rec_cell = f"[bold green]{rec_ver_str}[/bold green]"

        row_vals = [
            rec.package,
            rec.current_version,
            rec_cell,
            rec.latest_stable or "N/A",
        ]

        if AppState.DEBUG_MODE:
            lowest_cand = rec.minimum_known_safe or "N/A"
            if rec.rejected_candidates and lowest_cand in rec.rejected_candidates:
                lowest_cell = f"[red]{lowest_cand}[/red] ❌ Rejected"
            else:
                lowest_cell = lowest_cand
            row_vals.append(lowest_cell)

        row_vals.extend([
            f"[{conf_color}]{conf_val}[/{conf_color}]",
            f"[{risk_color}]{risk_val}[/{risk_color}]",
            f"{len(f_list)} CVEs"
        ])

        version_table.add_row(*row_vals)

    console.print(version_table)
    console.print()

    for rec in recommendations:
        if rec.recommended_version:
            conf_val = rec.confidence.value if hasattr(rec.confidence, "value") else str(rec.confidence)
            risk_val = rec.migration_risk.value if hasattr(rec.migration_risk, "value") else str(rec.migration_risk)

            lines = [
                f"[bold cyan]Package:[/bold cyan] {rec.package} [dim]({rec.ecosystem})[/dim]",
                f"[bold]Current Version:[/bold] {rec.current_version}  →  [bold green]Recommended:[/bold green] {rec.recommended_version} {'✅ Verified Safe' if rec.verified_safe else ''}",
                f"[bold yellow]Latest Stable:[/bold yellow] {rec.latest_stable or 'N/A'}",
                f"[bold]Verification:[/bold] {conf_val}",
                f"[bold]Migration Risk:[/bold] {risk_val}",
            ]

            if AppState.DEBUG_MODE:
                lowest_cand_str = rec.minimum_known_safe or 'N/A'
                if rec.rejected_candidates and lowest_cand_str in rec.rejected_candidates:
                    lowest_cand_str += " (Rejected)"
                lines.append(f"[bold green]Lowest Candidate Fix:[/bold green] {lowest_cand_str}")
                if rec.rejected_candidates:
                    lines.append(f"[bold red]Rejected Candidates:[/bold red] {', '.join(rec.rejected_candidates)}")
                if rec.recommendation_reason:
                    lines.append(f"[bold yellow]Reason:[/bold yellow] {rec.recommendation_reason}")

            lines.append(f"[bold green]Upgrade Command:[/bold green] {rec.upgrade_command}")

            panel_text = "\n".join(lines)

            console.print(Panel(
                panel_text,
                title=f"[bold white]Remediation Strategy — {rec.package}[/bold white]",
                border_style="cyan",
                box=box.ROUNDED,
                expand=False
            ))


SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "UNKNOWN": 0
}


def sort_canonical_findings(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    def sort_key(f: VulnerabilityFinding):
        f.normalize_severity()
        sev_rank = SEVERITY_RANK.get(f.cvss_severity.upper() if f.cvss_severity else "UNKNOWN", 0)
        epss_val = f.epss_score
        if not epss_val and f.epss_percent:
            try:
                epss_val = float(str(f.epss_percent).rstrip("%"))
            except (ValueError, AttributeError):
                epss_val = 0.0
        return (-f.risk_heat_score, -f.cvss_score, -sev_rank, -epss_val, f.cve_id or "")

    return sorted(findings, key=sort_key)


def print_findings_table(console, findings: List[VulnerabilityFinding], title: str = "Vulnerabilities", page_size: int = 20, page: int = 1):
    if not findings:
        console.print(f"[green]No findings in: {title}[/green]")
        return

    sorted_findings = sort_canonical_findings(findings)
    total_count = len(sorted_findings)
    if page_size > 0 and total_count > page_size:
        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_count)
        display_findings = sorted_findings[start_idx:end_idx]
        paging_info = f" (Showing {start_idx + 1}–{end_idx} of {total_count})"
    else:
        display_findings = sorted_findings
        start_idx = 0
        end_idx = total_count
        paging_info = f" (Showing 1–{total_count} of {total_count})" if total_count > 0 else ""

    table = Table(
        title=f"[bold]{title}[/bold]{paging_info}",
        border_style="cyan",
        show_lines=True,
        box=box.SQUARE,
    )
    table.add_column("Package",       style="bold white")
    table.add_column("CVE",           style="bold cyan")
    table.add_column("Severity",      justify="center")
    table.add_column("CVSS",          justify="right")
    table.add_column("EPSS",          justify="right", style="cyan")
    table.add_column("Risk",          justify="right")
    table.add_column("KEV",           justify="center")
    table.add_column("CWE",           style="yellow")
    table.add_column("ATT&CK",        style="bold red")

    for f in display_findings:
        sev_display = f.cvss_severity
        sev_color = get_severity_color(f.cvss_severity)
        
        cwe_disp = f.cwe_id if f.cwe_id else "—"
            
        mitre_text = "[dim]—[/dim]"
        if getattr(f, "attack_techniques", None) and len(f.attack_techniques) > 0:
            mitre_text = ", ".join([t.technique_id for t in f.attack_techniques])
            
        pkg_str = f"{f.package.name} {f.package.version}" if f.package else "Unknown"

        table.add_row(
            pkg_str,
            f.cve_id,
            f"[{sev_color}]{sev_display}[/{sev_color}]",
            f"[{sev_color}]{f.cvss_score}[/{sev_color}]",
            str(f.epss_percent),
            f"[{sev_color}]{f.risk_heat_score}[/{sev_color}]",
            format_kev(f),
            cwe_disp,
            mitre_text
        )

    console.print(table)
    if total_count > page_size and page_size > 0:
        console.print(f"[dim]Showing {start_idx + 1}–{end_idx} of {total_count} findings.[/dim]\n")
    else:
        mapped_att = sum(1 for f in sorted_findings if getattr(f, "attack_techniques", None))
        unmapped = total_count - mapped_att
        console.print(f"[dim]MITRE ATT&CK Coverage: {mapped_att}/{total_count} findings mapped ({unmapped} unmapped).[/dim]\n")


def render_all_findings_paginated(console, scan: Optional[ScanResult], page_size: int = 20, input_func=None):
    findings = scan.findings if (scan and scan.findings) else []
    if not findings:
        console.print(Panel(
            "[green]No vulnerabilities found.[/green]",
            title="[bold cyan]All Vulnerability Findings[/bold cyan]",
            box=box.SQUARE,
            expand=False
        ))
        if input_func:
            input_func("[Q] Back")
        return

    sorted_findings = sort_canonical_findings(findings)
    total_count = len(sorted_findings)
    page = 0

    while True:
        start_idx = page * page_size
        end_idx = min(start_idx + page_size, total_count)
        page_findings = sorted_findings[start_idx:end_idx]

        has_prev = page > 0
        has_next = end_idx < total_count

        title = f"All Vulnerability Findings (Showing {start_idx + 1}–{end_idx} of {total_count})"

        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            show_lines=True,
            box=box.SQUARE,
        )
        table.add_column("Package",       style="bold white")
        table.add_column("CVE",           style="bold cyan")
        table.add_column("Severity",      justify="center")
        table.add_column("CVSS",          justify="right")
        table.add_column("EPSS",          justify="right", style="cyan")
        table.add_column("Risk",          justify="right")
        table.add_column("KEV",           justify="center")
        table.add_column("CWE",           style="yellow")
        table.add_column("ATT&CK",        style="bold red")

        for f in page_findings:
            f.normalize_severity()
            sev_display = f.cvss_severity
            sev_color = get_severity_color(f.cvss_severity)
            cwe_disp = f.cwe_id if f.cwe_id else "—"
            mitre_text = "[dim]—[/dim]"
            if getattr(f, "attack_techniques", None) and len(f.attack_techniques) > 0:
                mitre_text = ", ".join([t.technique_id for t in f.attack_techniques])
            pkg_str = f"{f.package.name} {f.package.version}" if f.package else "Unknown"

            table.add_row(
                pkg_str,
                f.cve_id,
                f"[{sev_color}]{sev_display}[/{sev_color}]",
                f"[{sev_color}]{f.cvss_score}[/{sev_color}]",
                str(f.epss_percent),
                f"[{sev_color}]{f.risk_heat_score}[/{sev_color}]",
                format_kev(f),
                cwe_disp,
                mitre_text
            )

        console.print(table)
        console.print(f"[dim]Showing {start_idx + 1}–{end_idx} of {total_count} findings.[/dim]\n")

        nav_items = []
        if has_next:
            nav_items.append("[N] Next Page")
        if has_prev:
            nav_items.append("[P] Previous Page")
        nav_items.append("[Q] Back")

        nav_str = "    ".join(nav_items)
        console.print(f"{nav_str}\n")

        if input_func is not None:
            user_input = input_func(nav_str)
        else:
            try:
                import questionary
                user_input = questionary.text(f"Action ({'/'.join([i[1] for i in nav_items])}):").ask()
            except Exception:
                user_input = "Q"

        if not user_input:
            user_input = "Q"

        choice = str(user_input).strip().upper()

        if choice in ("N", "NEXT") and has_next:
            page += 1
        elif choice in ("P", "PREV", "PREVIOUS") and has_prev:
            page -= 1
        elif choice in ("Q", "QUIT", "BACK", "EXIT"):
            break
        else:
            if input_func is None:
                break


# ── Security Advisor UI ────────────────────────────────────────────────────────


def print_top_attack_paths(console, scan: ScanResult):
    if not getattr(scan, "attack_paths", []):
        return

    table = Table(
        title="[bold red]Top Attack Paths[/bold red]",
        border_style="red",
        box=box.SQUARE,
        show_lines=True,
    )
    table.add_column("Rank", justify="center", style="bold")
    table.add_column("Technology" if scan.target_type == "website" else "Package", style="bold cyan")
    table.add_column("Attack Path", style="white")
    table.add_column("Exposure", justify="center", style="bold red")

    top_paths = scan.attack_paths[:5]
    for i, path in enumerate(top_paths, 1):
        if path.attack_techniques:
            t_str = ", ".join([f"{t.technique_id} ({getattr(t, 'technique_name', None) or 'Technique name unavailable'})" for t in path.attack_techniques])
        else:
            t_str = "No Mapping"
        path_str = f"{path.cve_id} -> {t_str}"
        
        display_name = path.package_name
        if scan.target_type == "website":
            from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
            catalog_entry = TECHNOLOGY_CATALOG.get(path.package_name.lower())
            if catalog_entry:
                display_name = catalog_entry.get("display_name", path.package_name)
        
        table.add_row(
            str(i),
            f"{display_name}\n[dim]{path.package_version}[/dim]",
            path_str,
            str(path.exposure_score)
        )

    console.print(table)
    console.print()


def has_confirmed_public_poc(finding: VulnerabilityFinding) -> bool:
    """Returns True ONLY if a finding has positively confirmed public PoC evidence."""
    intel = getattr(finding, "exploit_intelligence", None)
    if not intel:
        return False
    if not bool(getattr(intel, "public_poc", False)):
        return False
    refs = getattr(intel, "exploit_references", None) or []
    source = getattr(intel, "poc_source", None)
    return bool(source) or bool(refs)


def print_exploit_intelligence_view(console, scan: ScanResult):
    """Display a dedicated exploit intelligence report showing ONLY confirmed PoC findings."""
    poc_findings = [
        f for f in scan.findings
        if has_confirmed_public_poc(f)
    ]

    if not poc_findings:
        console.print(Panel(
            "[dim]No confirmed public PoCs found for the scanned vulnerabilities.[/dim]",
            title="[bold yellow]Exploit Intelligence[/bold yellow]",
            border_style="yellow",
            box=box.SQUARE,
            expand=False
        ))
        return

    # Deduplicate by CVE ID
    seen: set = set()
    unique = []
    for f in poc_findings:
        if f.cve_id not in seen:
            seen.add(f.cve_id)
            unique.append(f)

    # Sort: Active Exploitation first, then Weaponized, Functional PoC
    maturity_order = {
        "Active Exploitation": 0,
        "Weaponized": 1,
        "Functional PoC": 2,
    }
    unique.sort(key=lambda f: maturity_order.get(
        f.exploit_intelligence.exploit_maturity if f.exploit_intelligence else "", 99))

    maturity_colors = {
        "Active Exploitation": "bold red",
        "Weaponized":          "bold dark_orange",
        "Functional PoC":      "bold yellow",
    }

    table = Table(
        title="[bold yellow]Exploit Intelligence — Public PoCs[/bold yellow]",
        border_style="yellow",
        box=box.SQUARE,
        show_lines=True,
    )
    table.add_column("CVE",              style="cyan",     min_width=18)
    table.add_column("Package",          style="bold",     min_width=16)
    table.add_column("Severity",         justify="center", min_width=12)
    table.add_column("Exploit Maturity", style="white",    min_width=22)
    table.add_column("Public PoC",       justify="center", min_width=14)
    table.add_column("Source",           style="dim",      min_width=12)

    for f in unique:
        intel = f.exploit_intelligence
        maturity = intel.exploit_maturity if intel else "Functional PoC"
        color = maturity_colors.get(maturity, "white")
        poc_display = "[bold green]✓ Available[/bold green]"
        source_display = (intel.poc_source if intel else None) or "GitHub"
        sev_color = get_severity_color(f.cvss_severity)

        table.add_row(
            f.cve_id,
            f"{f.package.name}\n[dim]{f.package.version}[/dim]" if f.package else "Unknown",
            f"[{sev_color}]{f.cvss_severity}[/{sev_color}]",
            f"[{color}]{maturity}[/{color}]",
            poc_display,
            source_display,
        )

    console.print()
    console.print(table)


def print_dependency_tree_view(console, scan: ScanResult):
    if not getattr(scan, "dependency_trees", None):
        console.print(Panel("[yellow]No dependency tree data available for this scan.[/yellow]", box=box.SQUARE))
        return

    console.print("\n[bold]Dependency Trees[/bold]")
    
    # Group trees by ecosystem
    eco_titles = {
        "python": "Python", "pypi": "Python",
        "npm": "Node.js", "node.js": "Node.js",
        "crates.io": "Rust", "rust": "Rust",
        "go": "Go",
        "rubygems": "Ruby", "ruby": "Ruby",
        "packagist": "Composer", "composer": "Composer",
        "maven": "Maven"
    }
    
    grouped = {}
    for node in scan.dependency_trees:
        eco = (node.ecosystem or "").lower()
        title = eco_titles.get(eco, node.ecosystem or "Unknown")
        if title not in grouped:
            grouped[title] = []
        grouped[title].append(node)
        
    for title, roots in sorted(grouped.items()):
        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        for root_node in roots:
            def build_rich_tree(node, rich_parent, depth=1):
                if depth > 2:
                    if node.children:
                        rich_parent.add(f"[dim][+ {len(node.children)} more descendants][/dim]")
                    return

                for child in node.children:
                    vuln_str = f" [red]({child.cve_count} CVEs)[/red]" if child.vulnerable else ""
                    style = "bold red" if child.vulnerable else "default"
                    child_tree = rich_parent.add(f"[{style}]{child.package_name} {child.version}[/{style}]{vuln_str}")
                    build_rich_tree(child, child_tree, depth + 1)

            vuln_str = f" [red]({root_node.cve_count} CVEs)[/red]" if root_node.vulnerable else ""
            style = "bold red" if root_node.vulnerable else "default"
            tree = Tree(f"[{style}]{root_node.package_name} {root_node.version}[/{style}]{vuln_str}")
            build_rich_tree(root_node, tree)
            console.print(tree)
    console.print()

def print_website_correlation_summary(console, scan: ScanResult):
    if not scan.website_assessment:
        return
        
    wa = scan.website_assessment
    from pulse.domain.models import CorrelationStatus, FindingSourceType
    
    status_colors = {
        CorrelationStatus.COMPLETED: "green",
        CorrelationStatus.PARTIAL: "yellow",
        CorrelationStatus.FAILED: "red",
        CorrelationStatus.RUNNING: "blue",
        CorrelationStatus.NOT_RUN: "white"
    }
    status_color = status_colors.get(wa.correlation_status, "white")
    status_str = f"[{status_color}]{wa.correlation_status.value}[/{status_color}]"
    
    text = []
    text.append(f"Status: {status_str}\n\n")
    
    if wa.correlation_status == CorrelationStatus.PARTIAL:
        total_processed = wa.correlated_technologies + wa.failed_technologies
        text.append(f"Processed: {total_processed}\n")
        text.append(f"Succeeded: {wa.correlated_technologies}\n")
        text.append(f"Failed: {wa.failed_technologies}\n\n")
    else:
        text.append(f"Technologies Correlated: {wa.correlated_technologies}\n\n")
        
    vuln_findings = [f for f in scan.findings if getattr(f, "source_type", None) == FindingSourceType.WEBSITE]
    vuln_count = len(vuln_findings)
    text.append(f"Vulnerabilities Found: {vuln_count}\n\n")
    
    highest_risk_tech = "None"
    if vuln_findings:
        highest_finding = max(vuln_findings, key=lambda f: f.risk_heat_score)
        tech_key = getattr(highest_finding, "source_asset", None)
        if tech_key:
            matching_tech = next((t for t in wa.technologies if t.name.lower() == tech_key.lower()), None)
            if matching_tech:
                from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
                catalog_entry = TECHNOLOGY_CATALOG.get(tech_key.lower())
                disp_name = catalog_entry.get("display_name", matching_tech.name) if catalog_entry else matching_tech.name
                highest_risk_tech = f"{disp_name} {matching_tech.version}" if matching_tech.version else disp_name
            else:
                highest_risk_tech = tech_key
                
    text.append(f"Highest Risk:\n{highest_risk_tech}")
    
    console.print(Panel(
        "".join(text),
        title="[bold]Website Correlation Summary[/bold]",
        border_style=status_color,
        box=box.SQUARE,
        expand=False
    ))


def print_website_assessment_summary(console, scan: ScanResult):
    if not scan.website_assessment:
        return
        
    wa = scan.website_assessment
    from pulse.domain.models import CorrelationStatus
    
    categories = {
        "CDN": [],
        "Backend": [],
        "Frontend": [],
        "Web Server": []
    }
    
    for t in wa.technologies:
        from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
        tech_key = t.name.lower()
        catalog_entry = TECHNOLOGY_CATALOG.get(tech_key)
        display_name = catalog_entry.get("display_name", t.name) if catalog_entry else t.name
        
        name_str = f"{display_name} {t.version}" if t.version else display_name
        cat_val = t.category.value if hasattr(t.category, "value") else str(t.category)
        
        if cat_val == "CDN":
            categories["CDN"].append(name_str)
        elif cat_val == "Web Server":
            categories["Web Server"].append(name_str)
        elif cat_val == "Frontend Library":
            categories["Frontend"].append(name_str)
        else:
            categories["Backend"].append(name_str)
            
    text = []
    text.append(f"Target:\n{wa.url}\n\n")
    text.append(f"Technologies Found: {len(wa.technologies)}\n\n")
    
    for cat in ["Frontend", "Backend", "CDN", "Web Server"]:
        items = categories[cat]
        if items or cat in ("Frontend", "Backend"):
            text.append(f"{cat}\n")
            if items:
                for item in items:
                    text.append(f" • {item}\n")
            else:
                text.append(" • None\n")
            text.append("\n")
            
    # Coverage — uses stored eligibility results (Single Source of Truth)
    from pulse.website.capability import CorrelationEligibilityStatus, evaluate_correlation_eligibility
    eligibilities = getattr(wa, 'technology_eligibilities', {})
    if eligibilities:
        elig_values = list(eligibilities.values())
    else:
        elig_values = [evaluate_correlation_eligibility(t) for t in wa.technologies]
    
    count_correlatable = sum(1 for e in elig_values if e.status in (CorrelationEligibilityStatus.CORRELATABLE, CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE))
    count_version_req = sum(1 for e in elig_values if e.status == CorrelationEligibilityStatus.VERSION_REQUIRED)
    count_detection = sum(1 for e in elig_values if e.status == CorrelationEligibilityStatus.DETECTION_ONLY)
    count_unavail = sum(1 for e in elig_values if e.status in (
        CorrelationEligibilityStatus.CORRELATION_UNAVAILABLE,
        CorrelationEligibilityStatus.INTELLIGENCE_UNAVAILABLE,
        CorrelationEligibilityStatus.RESOLUTION_FAILED,
        CorrelationEligibilityStatus.CONFIDENCE_TOO_LOW,
    ))
    
    text.append("Correlation\n")
    text.append(f" • Correlated: {count_correlatable}\n")
    if count_version_req > 0:
        text.append(f" • Version Required: {count_version_req}\n")
    if count_detection > 0:
        text.append(f" • Detection Only: {count_detection}\n")
    if count_unavail > 0:
        text.append(f" • Correlation Unavailable: {count_unavail}\n")
    text.append("\n")
    
    is_correlated = wa.correlation_status in (CorrelationStatus.COMPLETED, CorrelationStatus.PARTIAL)
    if is_correlated:
        total_vulns = len(getattr(scan, "findings", []))
        text.append("Vulnerability Intelligence\n")
        text.append(f" • Technologies Correlated: {wa.correlated_technologies}\n")
        text.append(f" • Vulnerabilities Found: {total_vulns}\n")
        if total_vulns > 0:
            highest_risk_finding = max(scan.findings, key=lambda f: f.risk_heat_score)
            text.append(f" • Highest Risk: {highest_risk_finding.package.name} {highest_risk_finding.package.version}\n")
    else:
        status_val = wa.correlation_status.value if hasattr(wa.correlation_status, "value") else str(wa.correlation_status)
        text.append(f"Vulnerability Correlation:\n • {status_val}")
    
    console.print(Panel(
        "".join(text),
        title="[bold]Website Assessment Summary[/bold]",
        border_style="cyan",
        box=box.SQUARE,
        expand=False
    ))


def print_technologies_view(console, scan: ScanResult):
    if not scan.website_assessment:
        return
        
    wa = scan.website_assessment
    from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
    from pulse.domain.models import CorrelationStatus, FindingSourceType
    
    is_correlated = wa.correlation_status in (CorrelationStatus.COMPLETED, CorrelationStatus.PARTIAL)
    
    title = "[bold blue]Technology Inventory[/bold blue]" if not is_correlated else "[bold blue]Technology Inventory & Vulnerability Status[/bold blue]"
    
    table = Table(
        title=title,
        border_style="blue",
        box=box.SQUARE,
        show_lines=True,
    )
    
    table.add_column("Technology", style="bold cyan")
    table.add_column("Version", style="green", justify="center")
    table.add_column("Category", style="dim")
    
    if not is_correlated:
        table.add_column("Confidence", justify="center")
        table.add_column("Coverage", justify="center")
    else:
        table.add_column("CVEs", justify="center", style="bold magenta")
        table.add_column("Risk", justify="center", style="bold red")
        table.add_column("Status", justify="center")
        
    from pulse.website.capability import CorrelationEligibilityStatus, evaluate_correlation_eligibility
    eligibilities = getattr(wa, 'technology_eligibilities', {})
    corr_results = getattr(wa, 'technology_correlation_results', {})
    
    for t in sorted(wa.technologies, key=lambda x: x.confidence, reverse=True):
        # Resolve display name
        tech_key = t.name.lower()
        catalog_entry = TECHNOLOGY_CATALOG.get(tech_key)
        display_name = catalog_entry.get("display_name", t.name) if catalog_entry else t.name
        
        # Coverage string — from stored eligibility (Single Source of Truth)
        tech_id = getattr(t, "signature_id", "") or tech_key
        elig = eligibilities.get(tech_id)
        if not elig:
            elig = evaluate_correlation_eligibility(t)
        coverage_str = elig.status.value
            
        version_str = t.version or "Unknown"
        
        if not is_correlated:
            # Confidence string formatting
            conf_band_style = {
                "VERIFIED": "bold green",
                "HIGH": "bold green",
                "MEDIUM": "bold yellow",
                "LOW": "dim"
            }.get(t.confidence_band.value if hasattr(t.confidence_band, "value") else str(t.confidence_band).upper(), "white")
            conf_band_val = t.confidence_band.value if hasattr(t.confidence_band, 'value') else t.confidence_band
            conf_str = f"[{conf_band_style}]{conf_band_val} ({t.confidence})[/{conf_band_style}]"
            
            table.add_row(
                display_name,
                version_str,
                t.category.value if hasattr(t.category, 'value') else str(t.category),
                conf_str,
                coverage_str
            )
        else:
            # Get structured correlation result
            c_res = corr_results.get(t.name)
            tech_findings = c_res.vulnerabilities if c_res else [
                f for f in getattr(scan, "findings", [])
                if getattr(f, "source_type", None) == FindingSourceType.WEBSITE
                and getattr(f, "source_asset", "").lower() == t.name.lower()
            ]
            cve_count = len(tech_findings)
            
            if c_res:
                corr_stat = c_res.correlation_status
            else:
                corr_stat = "VULNERABILITIES_FOUND" if cve_count > 0 else ("NO_KNOWN_VULNERABILITIES" if elig.is_eligible and elig.version_available else elig.status.value)

            if corr_stat == "VULNERABILITIES_FOUND":
                cve_display = str(cve_count)
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                highest_finding = max(tech_findings, key=lambda f: severity_order.get(f.cvss_severity.value.upper() if hasattr(f.cvss_severity, "value") else f.cvss_severity.upper(), 0))
                sev_name = highest_finding.cvss_severity.value.capitalize() if hasattr(highest_finding.cvss_severity, "value") else highest_finding.cvss_severity.capitalize()
                sev_color = {
                    "CRITICAL": "bold red",
                    "HIGH": "bold dark_orange",
                    "MEDIUM": "bold yellow",
                    "LOW": "bold green"
                }.get(highest_finding.cvss_severity.value.upper() if hasattr(highest_finding.cvss_severity, "value") else highest_finding.cvss_severity.upper(), "white")
                risk_display = f"[{sev_color}]{sev_name}[/{sev_color}]"
                status_display = "[bold red]Vulnerable[/bold red]"
            elif corr_stat == "NO_KNOWN_VULNERABILITIES":
                cve_display = "0"
                risk_display = "[green]None[/green]"
                status_display = "[bold green]Clean[/bold green]"
            elif corr_stat == "VERSION_REQUIRED":
                cve_display = "-"
                risk_display = "N/A"
                status_display = "[yellow]Version Req[/yellow]"
            elif corr_stat == "DETECTION_ONLY":
                cve_display = "-"
                risk_display = "N/A"
                status_display = "[dim]Detection Only[/dim]"
            else:
                cve_display = "-"
                risk_display = "N/A"
                status_display = "[red]Unavailable[/red]"
                
            table.add_row(
                display_name,
                version_str,
                t.category.value if hasattr(t.category, 'value') else str(t.category),
                cve_display,
                risk_display,
                status_display
            )
            
    console.print(table)
    console.print()
    
    # Print detailed Evidence Tree
    console.print("[bold blue]Technology Detection Evidence Tree[/bold blue]")
    roots = [t for t in wa.technologies if not t.parent]
    tech_map = {t.name: t for t in wa.technologies}
    
    def add_tech_node(tree_node, t):
        v_str = f" v{t.version}" if t.version else ""
        c_band = t.confidence_band.value if hasattr(t.confidence_band, 'value') else t.confidence_band
        header_text = f"[bold cyan]{t.name}[/bold cyan]{v_str} [dim]({t.category.value if hasattr(t.category, 'value') else t.category})[/dim] - [bold]{c_band}[/bold] ({t.confidence}%)"
        
        tech_branch = tree_node.add(header_text)
        
        if t.version_evidence:
            v_ev = t.version_evidence
            tech_branch.add(f"[green]Version Evidence ({v_ev.method.value if hasattr(v_ev.method, 'value') else v_ev.method}):[/green] [dim]{v_ev.source} -> {v_ev.value}[/dim] (Confidence: {v_ev.confidence}%)")
            
        if t.evidence:
            ev_branch = tech_branch.add("[bold yellow]Evidence Signals[/bold yellow]")
            for ev in t.evidence:
                rel_style = {
                    "VERIFIED": "bold green",
                    "HIGH": "green",
                    "MEDIUM": "yellow",
                    "LOW": "dim"
                }.get(ev.reliability.value if hasattr(ev.reliability, "value") else str(ev.reliability).upper(), "white")
                
                rel_str = f"[{rel_style}]Reliability: {ev.reliability.value if hasattr(ev.reliability, 'value') else ev.reliability}[/{rel_style}]"
                ev_branch.add(f"• [bold]{ev.method.value if hasattr(ev.method, 'value') else ev.method}[/bold] ({ev.source}): {ev.value} - [dim]{ev.description}[/dim] ({rel_str}, Confidence: {ev.confidence}%)")
                
        for child_name in t.children:
            child_fp = tech_map.get(child_name)
            if child_fp:
                add_tech_node(tech_branch, child_fp)
                
    root_tree = Tree("[bold green]Detected Web Stack[/bold green]")
    for r in roots:
        add_tech_node(root_tree, r)
        
    console.print(root_tree)
    console.print()
    
    # --- Technology Changes (Drift) View ---
    from pulse.history.history import HistoryService
    from pulse.website.inventory.delta import compare_inventory
    from pulse.website.inventory.service import TechnologyInventoryService
    try:
        inventory_service = TechnologyInventoryService()
        current_inventory = inventory_service.build_inventory(wa)
        
        history_service = HistoryService()
        prev_raw = history_service.get_previous_technologies(scan.target_type, scan.target_id)
        from pulse.website.inventory.models import InventoryTechnology
        prev_inventory = [InventoryTechnology(**item) for item in prev_raw]
        
        if prev_inventory:
            delta = compare_inventory(current_inventory, prev_inventory)
            if delta.added or delta.removed or delta.upgraded or delta.downgraded:
                console.print("[bold blue]Technology Changes[/bold blue]")
                for item in delta.added:
                    console.print(f"[green]+ {item}[/green]")
                for change in delta.upgraded:
                    console.print(f"[yellow]↑ {change.technology} {change.previous_version} -> {change.current_version}[/yellow]")
                for change in delta.downgraded:
                    console.print(f"[red]↓ {change.technology} {change.previous_version} -> {change.current_version}[/red]")
                for item in delta.removed:
                    console.print(f"[red]- {item}[/red]")
                console.print()
    except Exception:
        pass

def print_security_headers_view(console, scan: ScanResult):
    if not scan.website_assessment:
        return
        
    table = Table(
        title="[bold magenta]Security Headers Assessment[/bold magenta]",
        border_style="magenta",
        box=box.SQUARE,
        show_lines=True,
    )
    table.add_column("Header", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")
    
    for h in scan.website_assessment.security_headers:
        if h.status == "Present":
            status_str = "[bold green]Present[/bold green]"
        elif h.status == "Missing":
            status_str = "[bold red]Missing[/bold red]"
        else:
            status_str = f"[bold yellow]{h.status}[/bold yellow]"
            
        table.add_row(
            h.header_name,
            status_str,
            h.details
        )
        
    console.print(table)
    console.print()


def render_cve_details(console, finding: VulnerabilityFinding) -> None:
    """Renders a comprehensive, interactive CVE detail inspection view."""
    finding.normalize_severity()
    sev_color = get_severity_color(finding.cvss_severity)
    
    main_table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    main_table.add_column("Property", style="bold cyan", justify="right", min_width=22)
    main_table.add_column("Value")

    # 1. Basic Metadata
    main_table.add_row("CVE ID", f"[bold white]{finding.cve_id}[/bold white]")
    main_table.add_row("Package", f"[bold]{finding.package.name}[/bold] [dim]({finding.package.ecosystem})[/dim]")
    main_table.add_row("Affected Version", finding.package.version)
    main_table.add_row("Fix Version", f"[bold green]{finding.fix_version or 'N/A'}[/bold green]")
    main_table.add_row("Severity", f"[{sev_color}]{finding.cvss_severity}[/{sev_color}]")
    main_table.add_row("CVSS Score", f"[{sev_color}]{finding.cvss_score}[/{sev_color}]")
    main_table.add_row("CVSS Vector", f"[dim]{finding.cvss_vector or 'N/A'}[/dim]")
    main_table.add_row("Risk Heat Score", f"[bold magenta]{finding.risk_heat_score}[/bold magenta]")

    # 2. Intelligence Scores
    main_table.add_row("", "")
    main_table.add_row("[bold yellow]Threat Intelligence[/bold yellow]", "────────────────────────────────────────")
    main_table.add_row("EPSS Score / %", f"{finding.epss_score:.4f} ({finding.epss_percent})" if finding.epss_score else finding.epss_percent)
    main_table.add_row("CISA KEV Match", format_kev(finding))
    
    from pulse.vulnerability.cwe_registry import CWERegistry
    from pulse.state import AppState

    cwe_str = CWERegistry.format_cwe(finding.cwe_id, finding.cwe_name)
    main_table.add_row("CWE Classification", f"[yellow]{cwe_str}[/yellow]")

    # ATT&CK Techniques
    att_str = "No Mapping"
    if getattr(finding, "attack_techniques", None):
        lines = []
        for t in finding.attack_techniques:
            tech_name = getattr(t, "technique_name", None) or "Technique name unavailable"
            t_str = f"{t.technique_id} — {tech_name}"
            if AppState.DEBUG_MODE and getattr(t, "tactic", None):
                t_str += f" [dim](Tactic: {t.tactic})[/dim]"
            lines.append(t_str)
        att_str = "\n".join(lines)
    main_table.add_row("MITRE ATT&CK", f"[bold red]{att_str}[/bold red]")

    # 3. Exploit Intelligence
    main_table.add_row("", "")
    main_table.add_row("[bold yellow]Exploit Intelligence[/bold yellow]", "────────────────────────────────────────")
    intel = getattr(finding, "exploit_intelligence", None)
    if intel:
        poc_str = "[bold green]Yes[/bold green]" if intel.public_poc else "[dim]No[/dim]"
        main_table.add_row("Public PoC", poc_str)
        main_table.add_row("Exploit Maturity", f"[bold yellow]{intel.exploit_maturity}[/bold yellow]")
        main_table.add_row("PoC Source", intel.poc_source or "N/A")
    else:
        main_table.add_row("Public PoC", "[dim]No Published PoC[/dim]")

    # 4. Remediation Guidance
    main_table.add_row("", "")
    main_table.add_row("[bold yellow]Remediation Guidance[/bold yellow]", "────────────────────────────────────────")
    cmd = get_recommended_command(finding.package.name, finding.package.ecosystem)
    main_table.add_row("Upgrade Command", f"[bold green]{cmd}[/bold green]")
    if getattr(finding, "solution", None):
        main_table.add_row("Solution", f"[dim]{finding.solution}[/dim]")

    # 5. Description & References
    main_table.add_row("", "")
    main_table.add_row("[bold yellow]Description & References[/bold yellow]", "────────────────────────────────────────")
    raw_desc = clean_display_text(finding.description or finding.summary or "No description provided.")
    desc_wrapped = textwrap.fill(raw_desc, width=70)
    main_table.add_row("Description", desc_wrapped)

    refs = getattr(finding, "references", None) or ([finding.reference_url] if getattr(finding, "reference_url", None) else [])
    if refs:
        refs_str = "\n".join([f"• {url}" for url in refs[:5]])
        main_table.add_row("References", f"[dim]{refs_str}[/dim]")

    console.print(Panel(
        main_table,
        title=f"[bold cyan]Vulnerability Detail Inspection — {finding.cve_id}[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        expand=False
    ))


def render_all_packages_paginated(console, scan, page_size: int = 50, input_func=None):
    import questionary
    
    # Flatten packages from dependency trees
    packages = []
    if getattr(scan, "dependency_trees", None):
        def extract_pkgs(node):
            packages.append((node.package_name, node.version, node.ecosystem))
            for child in node.children:
                extract_pkgs(child)
        for root_node in scan.dependency_trees:
            extract_pkgs(root_node)
            
    # Deduplicate and sort
    packages = sorted(list(set(packages)), key=lambda x: (x[2] or "", x[0] or "", x[1] or ""))
    
    if not packages:
        console.print(Panel(
            "[yellow]No packages were found during this scan.[/yellow]",
            title="[bold cyan]Scanned Packages[/bold cyan]",
            box=box.SQUARE,
            expand=False
        ))
        if input_func:
            input_func("[Q] Back")
        return

    total_count = len(packages)
    page = 0

    while True:
        start_idx = page * page_size
        end_idx = min(start_idx + page_size, total_count)
        page_packages = packages[start_idx:end_idx]

        has_prev = page > 0
        has_next = end_idx < total_count

        title = f"Scanned Packages & Versions (Showing {start_idx + 1}–{end_idx} of {total_count})"

        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            show_lines=True,
            box=box.SQUARE,
        )
        table.add_column("Package Name", style="bold white")
        table.add_column("Version", style="bold green")
        table.add_column("Ecosystem", style="cyan")

        for pkg in page_packages:
            table.add_row(pkg[0], pkg[1] or "Unknown", pkg[2] or "Unknown")

        console.print(table)

        nav_choices = []
        if has_prev:
            nav_choices.append(questionary.Choice("Previous Page", "prev", shortcut_key="p"))
        if has_next:
            nav_choices.append(questionary.Choice("Next Page", "next", shortcut_key="n"))
        nav_choices.append(questionary.Choice("Back to Menu", "back", shortcut_key="b"))

        choice = (input_func or questionary.select("Navigation:", choices=nav_choices).ask)() if input_func else questionary.select("Navigation:", choices=nav_choices).ask()
        
        if choice == "prev" and has_prev:
            page -= 1
        elif choice == "next" and has_next:
            page += 1
        else:
            break
