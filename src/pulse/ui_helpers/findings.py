from pulse.domain.models import VulnerabilityFinding
from pulse.state import AppState
from pulse.vulnerability.cwe_registry import CWERegistry
from rich.table import Table

def get_severity_color(severity: str) -> str:
    sev = severity.upper()
    if sev == "CRITICAL": return "bold red"
    elif sev == "HIGH": return "bold dark_orange"
    elif sev == "MEDIUM": return "bold yellow"
    elif sev == "LOW": return "bold green"
    elif sev == "INFORMATIONAL": return "bold blue"
    return "white"

def format_kev(finding: VulnerabilityFinding) -> str:
    return "[bold red]ACTIVE EXPLOIT[/bold red]" if finding.kev_match else "[dim]No[/dim]"

def build_finding_context(table: Table, pkg, finding: VulnerabilityFinding, rec, sev_color: str, sev_display: str):
    table.add_row("Package", f"[bold]{pkg.name}[/bold]")
    table.add_row("Scanned Version", f"{pkg.version} [dim]({rec.status})[/dim]")
    table.add_row("CVE ID", finding.cve_id)
    cwe_str = CWERegistry.format_cwe(finding.cwe_id, finding.cwe_name)
    table.add_row("CWE Classification", f"[yellow]{cwe_str}[/yellow]")
    table.add_row("Severity", f"[{sev_color}]{sev_display}[/{sev_color}]")
    table.add_row("CVSS Score", f"[{sev_color}]{finding.cvss_score}[/{sev_color}]")
    if finding.epss_percent is not None:
        table.add_row("EPSS Percentile", str(finding.epss_percent))
    table.add_row("KEV Match", format_kev(finding))
    table.add_row("Risk Heat Score", f"[bold magenta]{finding.risk_heat_score}[/bold magenta]")

def build_vulnerability_summary(table: Table, finding: VulnerabilityFinding):
    table.add_row("", "")
    table.add_row("[bold yellow]Vulnerability Summary[/bold yellow]", "────────────────────────────────────────")
    vuln_desc = finding.description or finding.summary or "No vulnerability description available."
    table.add_row("", vuln_desc)

def build_attack_path(table: Table, finding: VulnerabilityFinding):
    table.add_row("", "")
    table.add_row("[bold yellow]Attack Path[/bold yellow]", "────────────────────────────────────────")
    if getattr(finding, "attack_techniques", None) and len(finding.attack_techniques) > 0:
        path_lines = [f"[bold red]{finding.cve_id}[/bold red]"]
        for tech in finding.attack_techniques:
            tech_name = getattr(tech, "technique_name", None) or "Technique name unavailable"
            tactic_str = f" [dim](Tactic: {tech.tactic})[/dim]" if (AppState.DEBUG_MODE and getattr(tech, "tactic", None)) else ""
            path_lines.append("  ↓")
            path_lines.append(f"[bold red]{tech.technique_id}[/bold red] — {tech_name}{tactic_str}")
        table.add_row("", "\\n".join(path_lines))
    else:
        table.add_row("", f"[bold red]{finding.cve_id}[/bold red]\\n  ↓\\n[dim]No ATT&CK mapping available[/dim]")

def build_upgrade_analysis(table: Table, pkg, rec):
    table.add_row("", "")
    table.add_row("[bold yellow]Upgrade Analysis[/bold yellow]", "────────────────────────────────────────")
    table.add_row("Current Version", pkg.version)
    table.add_row("Latest Stable", f"[bold green]{rec.latest_stable or 'Unknown'}[/bold green]")
    verif_badge = " [bold green]✅ Verified Safe[/bold green]" if rec.verified_safe else ""
    table.add_row("Recommended Version", f"[bold green]{rec.recommended_version or 'N/A'}[/bold green]{verif_badge}")
    risk_val = rec.migration_risk.value if hasattr(rec.migration_risk, "value") else str(rec.migration_risk)
    risk_color = "bold green" if risk_val == "LOW" else ("bold yellow" if risk_val == "MEDIUM" else "bold red")
    table.add_row("Migration Risk", f"[{risk_color}]{risk_val}[/{risk_color}]")
    conf_val = rec.confidence.value if hasattr(rec.confidence, "value") else str(rec.confidence)
    table.add_row("Verification", f"[bold green]{conf_val}[/bold green]")
    status_str = "[bold green]✅ Verified Safe[/bold green]" if rec.verified_safe else "[bold green]✓ Advisory Verified[/bold green]"
    table.add_row("Status", status_str)

    if AppState.DEBUG_MODE:
        table.add_row("", "")
        table.add_row("[bold yellow]Candidate Evaluation[/bold yellow]", "────────────────────────────────────────")
        lowest_candidate = rec.minimum_known_safe or 'None Available'
        if rec.rejected_candidates and lowest_candidate in rec.rejected_candidates:
            lowest_display = f"[bold red]{lowest_candidate}[/bold red] [yellow]❌ Rejected[/yellow]"
        else:
            lowest_display = f"[bold green]{lowest_candidate}[/bold green]"
        table.add_row("Lowest Candidate Fix", lowest_display)
        table.add_row("Reason", f"[dim]{rec.recommendation_reason}[/dim]")
        if rec.alternative_version:
            table.add_row("Alternative Path", f"[cyan]{rec.alternative_version}[/cyan]")
            table.add_row("Alternative Reason", f"[dim]{rec.alternative_reason}[/dim]")
        table.add_row("Suitability Rating", f"[bold yellow]{rec.suitability_rating}[/bold yellow]")
        if rec.rejected_candidates:
            table.add_row("Rejected Candidates", f"[yellow]✖ {', '.join(rec.rejected_candidates)} (vulnerabilities detected)[/yellow]")

    table.add_row("", "")
    cmd_header = "[bold yellow]Suggested Commands[/bold yellow]" if AppState.DEBUG_MODE else "[bold yellow]Upgrade Command[/bold yellow]"
    table.add_row(cmd_header, "────────────────────────────────────────")
    if AppState.DEBUG_MODE:
        if isinstance(rec.commands, list):
            for cmd in rec.commands:
                is_rec = getattr(cmd, 'recommended', False)
                star = "[bold green]★[/bold green] " if is_rec else "  "
                mgr = getattr(getattr(cmd, 'manager', 'pkg'), 'value', str(getattr(cmd, 'manager', 'pkg'))).upper()
                desc = getattr(cmd, 'description', '')
                cmd_str = getattr(cmd, 'command', str(cmd))
                table.add_row(f"{star}{mgr} ({desc})", f"[bold green]{cmd_str}[/bold green]")
        elif isinstance(rec.commands, dict):
            for k, v in rec.commands.items():
                table.add_row(k.capitalize(), f"[bold green]{v}[/bold green]")
    else:
        primary_cmd = rec.upgrade_command
        if primary_cmd:
            table.add_row("Recommended", f"[bold green]{primary_cmd}[/bold green]")
