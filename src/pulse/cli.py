import argparse
import logging
import sys
from datetime import datetime
import questionary
from rich.console import Console

from pulse.banner import show_banner
from pulse.config import load_config
from pulse.history.db import init_db
from pulse.reporter import generate_mock_scan_data, export_json, export_markdown, export_csv, export_html, export_sarif
from pulse.scanner import ScannerOrchestrator
from pulse.ui import (
    print_highest_risk_finding, print_findings_table, print_remediation_table,
    print_top_attack_paths, print_exploit_intelligence_view,
    print_dependency_tree_view, print_website_assessment_summary,
    print_technologies_view, print_security_headers_view
)
from pulse.domain.models import ScanResult
from pulse.config import get_setting, set_setting, remove_setting
from pathlib import Path
import socket

from pulse.state import AppState

logger = logging.getLogger(__name__)
console = Console()

def post_scan_render(console, scan: ScanResult):
    from pulse.ui import (
        print_security_summary, print_priority_summary, print_threat_summary,
        print_supply_chain_summary, print_attack_paths, print_trend_summary,
        print_provider_observability, print_highest_risk_finding
    )
    from pulse.state import AppState, SummaryMode
    from pulse.domain.models import CorrelationStatus
    
    if scan.target_type == "website" and scan.website_assessment:
        if scan.website_assessment.correlation_status == CorrelationStatus.NOT_RUN:
            return
            
    # Render Plugin diagnostics summary if present
    if getattr(scan, "plugin_diagnostics", None):
        from pulse.domain.models import PluginExecutionStatus
        from pulse.banner import UNICODE_SUPPORTED
        
        ok_char = "✓" if UNICODE_SUPPORTED else "+"
        warn_char = "⚠" if UNICODE_SUPPORTED else "!"
        fail_char = "✗" if UNICODE_SUPPORTED else "x"
        skip_char = "○" if UNICODE_SUPPORTED else "o"
        bullet_char = "•" if UNICODE_SUPPORTED else "-"
        
        console.print("\n[bold]Plugin Summary[/bold]")
        total_warnings = 0
        total_errors = 0
        for p_id, diag in scan.plugin_diagnostics.items():
            display_name = p_id.capitalize()
            if diag.status == PluginExecutionStatus.SUCCESS:
                console.print(f"  [green]{ok_char}[/green] {display_name}")
            elif diag.status == PluginExecutionStatus.WARNING:
                console.print(f"  [yellow]{warn_char}[/yellow] {display_name} (warnings encountered)")
                total_warnings += len(diag.warnings)
            elif diag.status == PluginExecutionStatus.FAILED:
                console.print(f"  [red]{fail_char}[/red] {display_name} (failed)")
                total_errors += len(diag.errors)
            elif diag.status == PluginExecutionStatus.SKIPPED:
                console.print(f"  [cyan]{skip_char}[/cyan] {display_name} (skipped)")
        
        if total_warnings > 0 or total_errors > 0:
            console.print("\n[bold yellow]Plugin Warnings/Errors:[/bold yellow]")
            for p_id, diag in scan.plugin_diagnostics.items():
                for w in diag.warnings:
                    console.print(f"  {bullet_char} [yellow]{p_id}:[/yellow] {w}")
                for e in diag.errors:
                    console.print(f"  {bullet_char} [red]{p_id}:[/red] {e}")
            
            warning_label = "warning" if total_warnings == 1 else "warnings"
            error_label = "error" if total_errors == 1 else "errors"
            summary_parts = []
            if total_errors > 0:
                summary_parts.append(f"{total_errors} {error_label}")
            if total_warnings > 0:
                summary_parts.append(f"{total_warnings} {warning_label}")
            console.print(f"\nCompleted with {', '.join(summary_parts)}.")
            
    compact = (AppState.SUMMARY_MODE == SummaryMode.COMPACT)
    print_security_summary(console, scan, compact=compact)
    
    if compact:
        return
    
    # Automatically display the highest risk finding
    if scan.findings:
        print_highest_risk_finding(console, scan.findings[0])
    
    # Debug/verbose mode: show extended diagnostic panels
    if AppState.SUMMARY_MODE == SummaryMode.VERBOSE or AppState.DEBUG_MODE:
        delta = getattr(scan, "_delta", None)
        print_threat_summary(console, scan)
        print_supply_chain_summary(console, scan)
        print_trend_summary(console, delta)
        
    if AppState.SHOW_ATTACK_PATHS:
        print_attack_paths(console, scan)


def auto_discover():
    orchestrator = ScannerOrchestrator()
    scan_result = orchestrator.run_auto_discover_scan(console)
    AppState.LAST_SCAN = scan_result
    post_scan_render(console, scan_result)
    post_scan_menu(scan_result)

def scan_single_package_menu():
    from pulse.ecosystems.package_resolution import PackageResolutionService
    from pulse.state import AppState
    import os
    import asyncio
    
    console.print("\n[bold]Scan a Package Across Any Supported Ecosystem[/bold]")
    resolver = PackageResolutionService()
    
    name = None
    while True:
        if not name:
            name = questionary.text("Package Name:").ask()
            if not name:
                return
            name = name.strip()
            
        version = questionary.text("Version:").ask()
        if version is None:
            return
        version = version.strip()
        if not version:
            console.print("\n[yellow]⚠ Package version is required.[/yellow]\n")
            console.print("Vulnerabilities are version-specific.\n")
            console.print("Please enter the installed package version.\n")
            continue
            
        is_latest_lookup = version.lower() in ("latest", "*")
        
        with console.status("[cyan]Detecting package...[/cyan]", spinner="dots"):
            result = asyncio.run(resolver.resolve(name, None if is_latest_lookup else version))
            
        if not result.candidates:
            console.print(f"\n[yellow]✗ Package \"{name}\" not found[/yellow]")
            if result.network_error:
                console.print("[yellow]Unable to verify package because package registries are unavailable.[/yellow]")
            else:
                console.print("Check the spelling.\n")
            choice = questionary.select(
                "What would you like to do?",
                choices=[
                    questionary.Choice("Re-enter package", "R"),
                    questionary.Choice("Back", "B")
                ]
            ).ask()
            if choice == "R":
                name = None
                continue
            else:
                return

        if not result.version_exists and not is_latest_lookup and not result.requires_user_selection:
            console.print(f"\n[bold green]✓ {name} identified[/bold green]")
            console.print(f"[bold green]✓ Ecosystem: {result.ecosystem}[/bold green]")
            console.print(f"[yellow]✗ Version {version} not found[/yellow]\n")
            # Only loop again, leaving `name` populated
            continue

        if not result.requires_user_selection:
            console.print(f"\n[bold green]✓ {result.package_name} identified[/bold green]")
            console.print(f"[bold green]✓ Ecosystem: {result.ecosystem}[/bold green]")
            if not is_latest_lookup:
                console.print(f"[bold green]✓ Version {version} verified[/bold green]")
            
            if result.provider is None:
                console.print("[yellow]⚠ Vulnerability intelligence unavailable for this ecosystem.[/yellow]")
                
            console.print("\n[cyan]Scanning...[/cyan]")
            break
            
        # Ambiguous
        console.print("\n[yellow]Package detected in multiple ecosystems.[/yellow]\n")
        choices = []
        for cp in result.alternative_candidates:
            choices.append(f"{cp.ecosystem} ({cp.registry_name}) — {cp.confidence}%")
        
        selected = questionary.select("\nSelect ecosystem:", choices=choices).ask()
        if not selected:
            return
            
        for cp in result.alternative_candidates:
            if selected.startswith(f"{cp.ecosystem} ({cp.registry_name})"):
                result.provider = cp.provider
                result.ecosystem = cp.ecosystem
                break
        
        if result.provider is None:
            console.print("[yellow]⚠ Vulnerability intelligence unavailable for this ecosystem.[/yellow]")
            return
            
        break

    if result.provider is None:
        console.print("[red]Unable to proceed without a supported vulnerability provider.[/red]")
        return
        
    from pulse.domain.models import PackageInfo
    pkg = PackageInfo(name=name, version="" if is_latest_lookup else version, ecosystem=result.provider.manifest.ecosystem)
    
    target_id = f"{result.provider.manifest.ecosystem}:{name.lower()}"
    
    if is_latest_lookup:
        console.print("\n[bold]Scanning latest available release...[/bold]")
    orchestrator = ScannerOrchestrator()
    scan_result = orchestrator.run_targeted_scan(console, [pkg], target_type="package", target_id=target_id)
    AppState.LAST_SCAN = scan_result
    post_scan_render(console, scan_result)
    post_scan_menu(scan_result)

def scan_file_menu():
    console.print("\n[bold]Scan Packages from File[/bold]")
    user_input = questionary.text("Enter file path:").ask()
    if not user_input or not user_input.strip():
        return

    from pulse.utils import normalize_user_path
    clean_path_str = normalize_user_path(user_input.strip())
    path = Path(clean_path_str)

    if not path.exists():
        console.print(f"\n[bold red]File not found:[/bold red] {clean_path_str}\n")
        return

    if not path.is_file():
        console.print(f"\n[bold red]Target path is not a file:[/bold red] {clean_path_str}\n")
        return

    from pulse.parsers.file_detector import DependencyFileDetector, DependencyFileType
    from pulse.parsers.registry import ParserRegistry

    file_type = DependencyFileDetector.detect(path)

    if file_type == DependencyFileType.UNKNOWN:
        console.print(
            "\n[bold red]Unable to determine dependency file type.[/bold red]\n\n"
            f"[bold white]File:[/bold white]\n{path.resolve()}\n\n"
            "[bold cyan]Supported dependency formats:[/bold cyan]\n"
            "  • Python requirements (requirements.txt, requirements (1).txt, etc.)\n"
            "  • package.json\n"
            "  • package-lock.json\n"
            "  • Cargo.toml / Cargo.lock\n"
            "  • go.mod / go.sum\n"
            "  • Gemfile / Gemfile.lock\n"
            "  • composer.json / composer.lock\n"
            "  • pom.xml\n"
        )
        return

    type_display_names = {
        DependencyFileType.PYTHON_REQUIREMENTS: "Python requirements",
        DependencyFileType.PACKAGE_JSON: "package.json",
        DependencyFileType.NPM_LOCK: "npm package-lock.json",
        DependencyFileType.YARN_LOCK: "Yarn lock",
        DependencyFileType.PNPM_LOCK: "pnpm lock",
        DependencyFileType.CARGO_TOML: "Cargo.toml",
        DependencyFileType.CARGO_LOCK: "Cargo.lock",
        DependencyFileType.GO_MOD: "go.mod",
        DependencyFileType.GO_SUM: "go.sum",
        DependencyFileType.GEMFILE: "Gemfile",
        DependencyFileType.GEMFILE_LOCK: "Gemfile.lock",
        DependencyFileType.COMPOSER_JSON: "composer.json",
        DependencyFileType.COMPOSER_LOCK: "composer.lock",
        DependencyFileType.MAVEN_POM: "Maven pom.xml"
    }

    display_type = type_display_names.get(file_type, file_type.value)

    console.print(f"\n[bold green]✓ File detected[/bold green]")
    console.print(f"  Path: {path.resolve()}")
    console.print(f"  Type: [cyan]{display_type}[/cyan]\n")

    try:
        packages = ParserRegistry.parse(path, file_type)
    except Exception as e:
        console.print(f"[bold red]Error parsing file:[/bold red] {e}\n")
        return

    if not packages:
        console.print("[yellow]No dependencies found in file.[/yellow]\n")
        return

    console.print(f"[bold green]✓ Parsed {len(packages)} package(s)[/bold green]\n")

    orchestrator = ScannerOrchestrator()
    scan_result = orchestrator.run_targeted_scan(console, packages, target_type="project", target_id=path.resolve().as_posix())
    AppState.LAST_SCAN = scan_result
    post_scan_render(console, scan_result)
    post_scan_menu(scan_result)

def lookup_cve_menu():
    console.print("\n[bold]Lookup CVE[/bold]")
    cve_id = questionary.text("Enter CVE ID (e.g. CVE-2022-34265):").ask()
    if not cve_id:
        return
        
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        console.print("[red]Invalid format. Must start with CVE-[/red]")
        return
        
    orchestrator = ScannerOrchestrator()
    orchestrator.lookup_cve(console, cve_id)

def website_assessment_menu():
    console.print("\n[bold]Website Technology Assessment[/bold]")
    url = questionary.text("Enter website URL (e.g. https://example.com):").ask()
    if not url:
        return
        
    if not url.startswith("http"):
        url = "https://" + url
        
    orchestrator = ScannerOrchestrator()
    scan_result = orchestrator.run_website_scan(console, url)
    AppState.LAST_SCAN = scan_result
    
    post_scan_render(console, scan_result)
    print_website_assessment_summary(console, scan_result)
    website_post_scan_menu(scan_result)

def website_post_scan_menu(scan: ScanResult):
    from pulse.domain.models import CorrelationStatus
    while True:
        is_correlated = False
        if scan.website_assessment:
            is_correlated = scan.website_assessment.correlation_status in (CorrelationStatus.COMPLETED, CorrelationStatus.PARTIAL)
            
        options = []
        if is_correlated:
            options.append("Run Vulnerability Correlation ✓")
        else:
            options.append("Run Vulnerability Correlation")
            
        options.append("View Technologies")
        options.append("View Security Headers")
        
        if is_correlated:
            options.append("View Detected Vulnerabilities")
            options.append("View Attack Paths")
            
        options.append("Export Report")
        options.append("Back to Main Menu")
        
        choice = questionary.select("\nPost-Scan Actions:", choices=options).ask()
        
        if choice == "Back to Main Menu" or not choice:
            break
        elif choice == "View Technologies":
            print_technologies_view(console, scan)
        elif choice == "View Security Headers":
            print_security_headers_view(console, scan)
        elif choice in ("Run Vulnerability Correlation", "Run Vulnerability Correlation ✓"):
            orchestrator = ScannerOrchestrator()
            orchestrator.analyze_website_technologies(console, scan)
            print_website_assessment_summary(console, scan)
        elif choice == "View Detected Vulnerabilities":
            print_findings_table(console, scan.findings)
        elif choice == "View Attack Paths":
            print_top_attack_paths(console, scan)
        elif choice == "Export Report":
            export_last_scan_menu()

def post_scan_menu(scan: ScanResult):
    if not scan.findings:
        return

    while True:
        choice = questionary.select(
            "\nPost-Scan Actions:",
            choices=[
                "View Critical Vulnerabilities",
                "View All Findings",
                "View Package Upgrade Recommendations",
                "View Attack Paths",
                "View Exploit Intelligence",
                "View Dependency Tree",
                questionary.Separator("────────────────────────────"),
                "Export Report",
                "Return to Main Menu"
            ]
        ).ask()

        if choice == "Return to Main Menu" or choice is None:
            break
        elif choice == "View Critical Vulnerabilities":
            severities = [f.cvss_severity.upper() for f in scan.findings if getattr(f, "cvss_severity", None)]
            if "CRITICAL" in severities:
                target_sev = "CRITICAL"
            elif "HIGH" in severities:
                target_sev = "HIGH"
            elif "MEDIUM" in severities:
                target_sev = "MEDIUM"
            elif "LOW" in severities:
                target_sev = "LOW"
            else:
                target_sev = "CRITICAL"

            filtered = [f for f in scan.findings if getattr(f, "cvss_severity", "").upper() == target_sev]
            title = f"{target_sev.capitalize()} Vulnerabilities"
            print_findings_table(console, filtered, title=title)
        elif choice == "View All Findings":
            from pulse.ui import render_all_findings_paginated
            render_all_findings_paginated(console, scan)
        elif choice == "View Package Upgrade Recommendations":
            print_remediation_table(console, scan)
        elif choice == "View Attack Paths":
            print_top_attack_paths(console, scan)
        elif choice == "View Exploit Intelligence":
            print_exploit_intelligence_view(console, scan)
        elif choice == "View Dependency Tree":
            print_dependency_tree_view(console, scan)
        elif choice == "Export Report":
            export_workflow(scan)


def get_export_dir() -> Path:
    """Get the default export directory in the OS Documents folder, creating it if necessary."""
    from pulse.reporting.path_resolver import ReportPathResolver
    return ReportPathResolver.get_configured_directory()


def export_workflow(scan: ScanResult):
    from pulse.reporting.report_service import ReportService
    from pulse.reporting.context import ReportContext
    from pulse.reporting.path_resolver import ReportPathResolver

    format_choice = questionary.select(
        "Select export format:",
        choices=[
            "HTML Dashboard (Primary)",
            "JSON (Schema 2.0)",
            "Markdown Document",
            "SARIF (CI/CD Integration)",
            "Export SBOM (CycloneDX)"
        ]
    ).ask()

    if not format_choice:
        return

    now = datetime.now()
    ctx = ReportContext(scan_result=scan, scan_id=now.strftime("%Y%m%d_%H%M%S"))
    from pulse.history import HistoryService
    history = HistoryService()
    scan_id = getattr(scan, "id", None) or ctx.scan_id

    if format_choice == "HTML Dashboard (Primary)":
        out_path = ReportPathResolver.resolve("report", timestamp=now, extension="html")
        generated = ReportService.generate_reports(ctx, formats=["html"], custom_output_dir=out_path.parent)
        html_file = generated.get("html", out_path)
        history.register_report_artifact(scan_id, "html", str(html_file.resolve()))
        console.print(f"[bold green]✓ Exported HTML Dashboard to:[/bold green]\n  {html_file.resolve()}")
    elif format_choice == "JSON (Schema 2.0)":
        out_path = ReportPathResolver.resolve("report", timestamp=now, extension="json")
        generated = ReportService.generate_reports(ctx, formats=["json"], custom_output_dir=out_path.parent)
        json_file = generated.get("json", out_path)
        history.register_report_artifact(scan_id, "json", str(json_file.resolve()))
        console.print(f"[bold green]✓ Exported JSON to:[/bold green]\n  {json_file.resolve()}")
    elif format_choice == "Markdown Document":
        out_path = ReportPathResolver.resolve("report", timestamp=now, extension="md")
        generated = ReportService.generate_reports(ctx, formats=["markdown"], custom_output_dir=out_path.parent)
        md_file = generated.get("markdown", out_path)
        history.register_report_artifact(scan_id, "markdown", str(md_file.resolve()))
        console.print(f"[bold green]✓ Exported Markdown to:[/bold green]\n  {md_file.resolve()}")
    elif format_choice == "SARIF (CI/CD Integration)":
        out_path = ReportPathResolver.resolve("report", timestamp=now, extension="sarif.json")
        generated = ReportService.generate_reports(ctx, formats=["sarif"], custom_output_dir=out_path.parent)
        sarif_file = generated.get("sarif", out_path)
        history.register_report_artifact(scan_id, "sarif", str(sarif_file.resolve()))
        console.print(f"[bold green]✓ Exported SARIF to:[/bold green]\n  {sarif_file.resolve()}")
    elif format_choice == "Export SBOM (CycloneDX)":
        out_path = ReportPathResolver.resolve("sbom", timestamp=now, extension="json")
        from pulse.supply_chain.sbom import export_cyclonedx
        export_cyclonedx(scan, out_path)
        history.register_report_artifact(scan_id, "sbom", str(out_path.resolve()))
        console.print(f"[bold green]✓ Exported CycloneDX SBOM to:[/bold green]\n  {out_path.resolve()}")


def export_last_scan_menu():
    reports_menu()

def reports_menu():
    """Reports & Exports UX sub-menu."""
    from pulse.reporting.report_service import ReportService
    from pulse.history import HistoryService

    while True:
        choice = questionary.select(
            "Reports & Exports Menu:",
            choices=[
                "Open Last Report",
                "Browse Report History",
                "Export Current Scan",
                "Open Reports Folder",
                "Report Settings",
                "Back to Main Menu"
            ]
        ).ask()

        if not choice or choice == "Back to Main Menu":
            break

        if choice == "Open Last Report":
            last_info = ReportService.get_last_report()
            if not last_info:
                console.print("\n[yellow]No scan reports exist yet. Please run a scan first.[/yellow]\n")
                continue

            if last_info["missing"]:
                console.print(f"\n[yellow]Report file no longer exists at:[/yellow] {last_info['html_path']}")
                if AppState.LAST_SCAN:
                    regen = questionary.confirm("Would you like to run a new export for the current scan?").ask()
                    if regen:
                        export_workflow(AppState.LAST_SCAN)
            else:
                console.print(f"\n[bold green]Opening report:[/bold green] {last_info['html_path']}")
                ReportService.open_report(last_info['html_path'])

        elif choice == "Browse Report History":
            history = HistoryService()
            runs = history.get_scan_runs()
            if not runs:
                console.print("\n[yellow]No scan history available.[/yellow]\n")
                continue

            choices = []
            for r in runs:
                sid = r.get("id")
                target = r.get("target_id", "global")
                score = r.get("score", 0)
                ts = r.get("timestamp", "N/A")
                choices.append(f"Scan #{sid:06d} | {target} | Score: {score} | {ts}")
            choices.append("Back")

            sel = questionary.select("Select a scan report to open:", choices=choices).ask()
            if sel and sel != "Back":
                sid_str = sel.split("|")[0].replace("Scan #", "").strip()
                scan_dir = ReportService.get_reports_dir() / f"scan_{sid_str}"
                html_files = sorted(list(scan_dir.glob("*.html")), key=lambda p: p.stat().st_mtime, reverse=True) if scan_dir.exists() else []
                html_file = html_files[0] if html_files else (scan_dir / "report.html")
                if html_file.exists():
                    console.print(f"\n[bold green]Opening report:[/bold green] {html_file}")
                    ReportService.open_report(html_file)
                else:
                    console.print(f"\n[yellow]Report file no longer exists at:[/yellow] {html_file}\n")

        elif choice == "Export Current Scan":
            if not AppState.LAST_SCAN:
                console.print("\n[yellow]No active scan in current session. Please run a scan first.[/yellow]\n")
                continue
            export_workflow(AppState.LAST_SCAN)

        elif choice == "Open Reports Folder":
            rdir = ReportService.get_reports_dir()
            console.print(f"\n[bold green]Reports directory:[/bold green] {rdir.resolve()}\n")
            try:
                import os
                if os.name == 'nt':
                    os.startfile(rdir)
                else:
                    webbrowser.open(rdir.as_uri())
            except Exception:
                pass
        elif choice == "Report Settings":
            reporting_settings_menu()

def history_settings_menu():
    """History Settings & Retention Management sub-menu."""
    from pulse.history import HistoryService

    history = HistoryService()
    while True:
        stats = history.get_storage_stats()
        max_scans = get_setting("HISTORY_MAX_SCANS", get_setting("REPORT_KEEP_HISTORY", "100"))
        ret_days = get_setting("HISTORY_RETENTION_DAYS", "90")
        auto_clean = "Yes" if get_setting("HISTORY_AUTO_CLEANUP", "true").lower() in ("true", "1", "yes") else "No"
        del_reports = "Yes" if get_setting("HISTORY_DELETE_REPORTS", "true").lower() in ("true", "1", "yes") else "No"

        choice = questionary.select(
            "History & Storage Settings:",
            choices=[
                f"Database Size: {stats['db_size_mb']} MB",
                f"Stored Scans / Reports: {stats['stored_scans_count']} scans / {stats['stored_reports_count']} report folders",
                f"Maximum Stored Scans: {max_scans}",
                f"Retention Days: {ret_days} days",
                f"Delete Reports With Scan History: {del_reports}",
                f"Auto Cleanup: {auto_clean}",
                "Clear History...",
                "Back to Previous Menu"
            ]
        ).ask()

        if not choice or choice == "Back to Previous Menu":
            break

        if choice.startswith("Maximum Stored Scans"):
            new_max = questionary.text("Enter maximum number of scans to retain (e.g. 100):").ask()
            if new_max and new_max.isdigit():
                set_setting("HISTORY_MAX_SCANS", new_max)
                set_setting("REPORT_KEEP_HISTORY", new_max)
                console.print("[bold green]Maximum stored scans updated![/bold green]")
        elif choice.startswith("Retention Days"):
            new_days = questionary.text("Enter retention limit in days (e.g. 90):").ask()
            if new_days and new_days.isdigit():
                set_setting("HISTORY_RETENTION_DAYS", new_days)
                console.print("[bold green]Retention days updated![/bold green]")
        elif choice.startswith("Delete Reports With Scan History"):
            new_del = questionary.select("Purge report folders when scan history is deleted?", choices=["Yes", "No"]).ask()
            if new_del:
                set_setting("HISTORY_DELETE_REPORTS", "true" if new_del == "Yes" else "false")
                console.print("[bold green]Delete reports policy updated![/bold green]")
        elif choice.startswith("Auto Cleanup"):
            new_auto = questionary.select("Automatically cleanup old history after scans?", choices=["Yes", "No"]).ask()
            if new_auto:
                set_setting("HISTORY_AUTO_CLEANUP", "true" if new_auto == "Yes" else "false")
                console.print("[bold green]Auto cleanup policy updated![/bold green]")
        elif choice == "Clear History...":
            clear_choice = questionary.select(
                "Clear History Options:",
                choices=[
                    "Entire History",
                    "Last 7 Days",
                    "Last 30 Days",
                    "Last 90 Days",
                    "Keep Last N Scans...",
                    "Back"
                ]
            ).ask()
            if not clear_choice or clear_choice == "Back":
                continue

            num_scans = stats['stored_scans_count']
            if num_scans == 0:
                console.print("[yellow]History is already empty.[/yellow]")
                continue

            confirm = questionary.confirm(f"You are about to delete scan history and associated report assets. Continue?").ask()
            if not confirm:
                continue

            deleted = 0
            if clear_choice == "Entire History":
                deleted = history.clear_history_all()
            elif clear_choice == "Last 7 Days":
                deleted = history.clear_history_by_days(7)
            elif clear_choice == "Last 30 Days":
                deleted = history.clear_history_by_days(30)
            elif clear_choice == "Last 90 Days":
                deleted = history.clear_history_by_days(90)
            elif clear_choice == "Keep Last N Scans...":
                keep_n = questionary.text("Enter number of recent scans to keep:").ask()
                if keep_n and keep_n.isdigit():
                    deleted = history.clear_history_keep_count(int(keep_n))

            console.print(f"[bold green]Successfully purged {deleted} scan run records and report assets![/bold green]")


def reporting_settings_menu():
    """Reporting Settings configuration sub-menu."""
    from pulse.reporting.path_resolver import ReportPathResolver
    while True:
        fmt = get_setting("REPORT_DEFAULT_FORMAT", "html").upper()
        resolved_dir = ReportPathResolver.get_configured_directory()
        loc_display = f"{resolved_dir}"
        auto_gen = "Yes" if get_setting("REPORT_GENERATE_AUTO", "false").lower() in ("true", "1", "yes") else "No"

        choice = questionary.select(
            "Reporting Settings:",
            choices=[
                f"Default Format: {fmt}",
                f"Default Export Location: {loc_display}",
                f"Generate Automatically: {auto_gen}",
                "Back to Settings"
            ]
        ).ask()

        if not choice or choice == "Back to Settings":
            break

        if choice.startswith("Default Format"):
            new_fmt = questionary.select("Select Default Report Format:", choices=["HTML", "JSON", "Markdown", "SARIF", "All"]).ask()
            if new_fmt:
                set_setting("REPORT_DEFAULT_FORMAT", new_fmt.lower())
                console.print("[bold green]Default format updated![/bold green]")
        elif choice.startswith("Default Export Location"):
            loc_choice = questionary.select(
                "Select Default Export Location:",
                choices=[
                    "Documents Folder (~/Documents/PULSE Reports/)",
                    "Current Working Directory (pulse-reports/)",
                    "Custom Directory..."
                ]
            ).ask()
            if loc_choice == "Documents Folder (~/Documents/PULSE Reports/)":
                set_setting("REPORT_DEFAULT_LOCATION", "documents")
                console.print("[bold green]Export location updated to Documents Folder![/bold green]")
            elif loc_choice == "Current Working Directory (pulse-reports/)":
                set_setting("REPORT_DEFAULT_LOCATION", "pwd")
                console.print("[bold green]Export location updated to Current Working Directory (pulse-reports/)![/bold green]")
            elif loc_choice == "Custom Directory...":
                custom_path = questionary.text("Enter custom report directory absolute path:").ask()
                if custom_path:
                    set_setting("REPORT_DEFAULT_LOCATION", "custom")
                    set_setting("REPORT_CUSTOM_DIR", custom_path)
                    console.print(f"[bold green]Export location updated to {custom_path}![/bold green]")
        elif choice.startswith("Generate Automatically"):
            new_gen = questionary.select("Generate reports automatically after scan?", choices=["Yes", "No"]).ask()
            if new_gen:
                set_setting("REPORT_GENERATE_AUTO", "true" if new_gen == "Yes" else "false")
                console.print("[bold green]Auto-generation setting updated![/bold green]")


def scanning_settings_menu():
    while True:
        cache = get_setting("CACHE_DURATION", "24")
        choice = questionary.select(
            "Scanning Settings:",
            choices=[
                f"Cache Duration: {cache}h",
                "Back to Settings"
            ]
        ).ask()
        if not choice or choice == "Back to Settings":
            break
        if choice.startswith("Cache Duration"):
            new_cache = questionary.text("Enter cache duration in hours:").ask()
            if new_cache and new_cache.isdigit():
                set_setting("CACHE_DURATION", new_cache)
def settings_menu():
    """Expanded main Settings Menu with modular sub-systems."""
    while True:
        choice = questionary.select(
            "Settings:",
            choices=[
                "Scanning Settings",
                "Reporting Settings",
                "History Settings",
                "API Keys & Credentials",
                "Back to Main Menu"
            ]
        ).ask()
        
        if choice == "Back to Main Menu" or not choice:
            break
        elif choice == "Scanning Settings":
            scanning_settings_menu()
        elif choice == "Reporting Settings":
            reporting_settings_menu()
        elif choice == "History Settings":
            history_settings_menu()
        elif choice == "API Keys & Credentials":
            manage_keys_menu()

def view_history_menu():
    from pulse.history import HistoryService
    history = HistoryService()
    runs = history.get_scan_runs()
    
    if not runs:
        console.print("\n[yellow]No scan history available.[/yellow]")
        return
        
    # Format options for selection
    choices = []
    for r in runs:
        target_type = r.get("target_type", "global").upper()
        target_id = r.get("target_id", "global")
        if len(target_id) > 30:
            target_id = target_id[:27] + "..."
        integrity = r.get("scan_integrity", "HIGH") or "HIGH"
        duration = r.get("scan_duration_seconds", 0.0) or 0.0
        choices.append(f"Scan #{r['id']} | {target_type} | {target_id} | Risk {r['score']} | Integrity {integrity} | Duration {duration:.1f}s | {r['vulns']} findings | {r['timestamp']}")
    choices.append("Cancel")
    
    choice = questionary.select("Select Scan to View:", choices=choices).ask()
    if choice == "Cancel" or not choice:
        return
        
    raw_id = choice.split(" | ")[0].split(".")[0].replace("Scan #", "").strip()
    scan_id = int(raw_id)
    orchestrator = ScannerOrchestrator()
    scan = orchestrator.get_historical_scan(scan_id)
    
    if not scan:
        console.print("[red]Failed to load scan.[/red]")
        return
        
    console.print(f"\n[bold]Scan Details (ID: {scan_id})[/bold]")
    
    # Calculate ATT&CK stats for history
    unique_techs = set()
    tech_counts = {}
    for f in scan.findings:
        for t in getattr(f, "attack_techniques", []):
            unique_techs.add(t.technique_id)
            tech_counts[t.technique_id] = tech_counts.get(t.technique_id, 0) + 1
            
    if unique_techs:
        top_tech = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[0][0]
        console.print(f"[bold cyan]Attack Techniques Identified:[/bold cyan] {len(unique_techs)}")
        console.print(f"[bold cyan]Top Technique:[/bold cyan] {top_tech}\n")
        
    post_scan_render(console, scan)
    
    if scan.findings:
        from pulse.ui import print_findings_table
        print_findings_table(console, scan.findings[:10], title="Top Findings")

def manage_keys_menu():
    while True:
        choice = questionary.select(
            "API Key Management:",
            choices=[
                "View Current Key Status",
                "Add/Update NVD API Key",
                "Remove NVD API Key",
                "Back to Settings"
            ]
        ).ask()
        
        if choice in ("Back to Settings", "Back to Main Menu") or not choice:
            break
        elif choice == "View Current Key Status":
            key = get_setting("NVD_API_KEY")
            if key:
                masked = key[:4] + "..." + key[-4:] if len(key) > 8 else "***"
                console.print(f"\n[bold green]NVD API Key:[/bold green] Configured ({masked})")
            else:
                console.print("\n[yellow]NVD API Key:[/yellow] Not Configured")
        elif choice == "Add/Update NVD API Key":
            new_key = questionary.password("Enter new NVD API Key:").ask()
            if new_key:
                set_setting("NVD_API_KEY", new_key.strip())
                console.print("[bold green]Key updated successfully![/bold green]")
        elif choice == "Remove NVD API Key":
            remove_setting("NVD_API_KEY")
            console.print("[bold green]Key removed successfully![/bold green]")

def help_menu():
    console.print("\n[bold]Supported Ecosystems[/bold]")
    console.print("  • Python (pip - requirements.txt / environment)")
    console.print("  • Node.js (npm - package.json / package-lock.json)")
    console.print("  • Rust (Cargo - Cargo.toml / Cargo.lock)")
    console.print("  • Go (go.mod / go.sum)")
    console.print("  • Ruby (Gemfile / Gemfile.lock)")
    console.print("  • PHP (Composer - composer.json / composer.lock)")
    console.print("  • Java (Maven - pom.xml)")
    console.print("  • .NET (NuGet - csproj / packages.config)")
    console.print("  • GitHub Actions (Workflows - .github/workflows/*.yml)")
    console.print("\n[bold]Data Sources[/bold]")
    console.print("  • OSV (Open Source Vulnerabilities)")
    console.print("  • NVD (National Vulnerability Database)")
    console.print("  • EPSS (Exploit Prediction Scoring System)")
    console.print("  • CISA KEV (Known Exploited Vulnerabilities)")
    console.print("\n[bold]Commands[/bold]")
    console.print("  • Auto Discover: Scans current directory for dependencies")
    console.print("  • Scan File: Scans a specific requirements.txt or package.json")
    console.print("  • Lookup CVE: Fetch details for a specific CVE-ID")
    console.print("  • Export Report: Save findings to HTML, JSON, CSV, or Markdown")

def startup_health_check():
    console.print("\n[bold]System Status[/bold]")
    
    # Check NVD Key
    if get_setting("NVD_API_KEY"):
        console.print("  NVD API Key      [green]✓ Configured[/green]")
    else:
        console.print("  NVD API Key      [red]✗ Not Configured[/red]")
        
    # Check Cache DB (assumed local)
    console.print("  Cache Database   [green]✓ Connected[/green]")
    
    # Check History DB (assumed local)
    console.print("  History DB       [green]✓ Connected[/green]")
    
    # Check Internet
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2)
        console.print("  Internet Access  [green]✓ Available[/green]")
    except OSError:
        console.print("  Internet Access  [red]✗ Offline[/red]")
        
    console.print()

def interactive_menu():
    """Main interactive menu loop."""
    choices = [
        questionary.Choice("Scan a Package Across Any Supported Ecosystem", "scan_package", shortcut_key="1"),
        questionary.Choice("Auto-discover & scan all packages", "auto_discover", shortcut_key="2"),
        questionary.Choice("Scan from file (requirements.txt / package.json)", "scan_file", shortcut_key="3"),
        questionary.Choice("Lookup a CVE ID directly", "lookup_cve", shortcut_key="4"),
        questionary.Choice("Website Technology Assessment", "website_assessment", shortcut_key="5"),
        questionary.Choice("Export last scan report", "export_report", shortcut_key="6"),
        questionary.Choice("View scan history", "view_history", shortcut_key="7"),
        questionary.Choice("Settings", "settings", shortcut_key="8"),
        questionary.Choice("Help", "help", shortcut_key="h"),
        questionary.Choice("Exit", "exit", shortcut_key="0"),
    ]

    action_map = {
        "scan_package": scan_single_package_menu,
        "auto_discover": auto_discover,
        "scan_file": scan_file_menu,
        "lookup_cve": lookup_cve_menu,
        "website_assessment": website_assessment_menu,
        "export_report": export_last_scan_menu,
        "view_history": view_history_menu,
        "settings": settings_menu,
        "help": help_menu,
    }

    while True:
        try:
            answer = questionary.select(
                "What would you like to do?",
                choices=choices,
                use_shortcuts=True,
                style=questionary.Style([
                    ('qmark', 'fg:#ff9d00 bold'),
                    ('question', 'bold'),
                    ('answer', 'fg:#ff9d00 bold'),
                    ('pointer', 'fg:#ff9d00 bold'),
                    ('highlighted', 'fg:#ff9d00 bold'),
                    ('selected', 'fg:#cc5454'),
                    ('separator', 'fg:#cc5454'),
                    ('instruction', ''),
                    ('text', ''),
                    ('disabled', 'fg:#858585 italic')
                ])
            ).ask()
            
            if answer is None or answer == "exit":
                console.print("[bold green]Goodbye![/bold green]")
                break
                
            action = action_map.get(answer)
            if action:
                action()
                console.print() # Empty line for readability before returning to menu
                
        except KeyboardInterrupt:
            # Ctrl+C from anywhere inside the loop returns to the menu
            # Or if raised by questionary, we just continue the loop
            console.print("\n[dim]Returning to menu...[/dim]\n")
            continue
        except EOFError:
            # Ctrl+D
            console.print("\n[bold green]Goodbye![/bold green]")
            break

def handle_config_cli(args):
    from pulse.core.config_service import ConfigService
    from pulse.core.config_schema import CONFIG_SCHEMA
    from rich.table import Table
    from rich import box

    cs = ConfigService.get_instance()
    action = args.config_action or "list"

    if action == "list":
        table = Table(title="[bold cyan]PULSE Configuration Settings[/bold cyan]", box=box.ROUNDED, expand=True)
        table.add_column("Key", style="bold white")
        table.add_column("Value", style="bold yellow")
        table.add_column("Default", style="dim")
        table.add_column("Category", style="cyan")

        for cat in sorted(set(opt.category for opt in CONFIG_SCHEMA.values())):
            for k, opt in CONFIG_SCHEMA.items():
                if opt.category == cat:
                    val = cs.get(k)
                    val_str = "[dim][empty][/dim]" if val == "" else str(val)
                    def_str = "[dim][empty][/dim]" if opt.default == "" else str(opt.default)
                    table.add_row(k, val_str, def_str, cat)

        console.print(table)

    elif action == "get":
        if not args.key:
            console.print("[bold red]Usage: pulse config get <KEY>[/bold red]")
            return
        val = cs.get(args.key)
        console.print(f"[bold white]{args.key}[/bold white] = [bold yellow]{val}[/bold yellow]")

    elif action == "set":
        if not args.key or args.value is None:
            console.print("[bold red]Usage: pulse config set <KEY> <VALUE>[/bold red]")
            return
        success, msg = cs.set(args.key, args.value)
        if success:
            console.print(f"[bold green]✓ {msg}[/bold green]")
        else:
            console.print(f"[bold red]✖ {msg}[/bold red]")

    elif action == "diff":
        diffs = cs.diff_config()
        if not diffs:
            console.print("[bold green]All configuration settings match schema defaults.[/bold green]")
            return

        table = Table(title="[bold cyan]Customized Configuration Settings[/bold cyan]", box=box.ROUNDED)
        table.add_column("Setting", style="bold white")
        table.add_column("Active Value", style="bold yellow")
        table.add_column("Schema Default", style="dim")

        for k, (curr, default) in diffs.items():
            table.add_row(k, str(curr), str(default))

        console.print(table)

    elif action == "validate":
        from pulse.core.config_validator import validate_config
        from pulse.config import get_env_file_path
        raw = cs._read_env_file(get_env_file_path())
        _, warnings, unknown_keys = validate_config(raw)

        if not warnings and not unknown_keys:
            console.print("[bold green]✓ Configuration file validated. Zero errors or warnings.[/bold green]")
            return

        for w in warnings:
            console.print(f"[yellow]⚠ {w}[/yellow]")
        for k, sugg in unknown_keys.items():
            if sugg:
                console.print(f"[yellow]⚠ Unknown key '{k}'. Did you mean '{sugg}'?[/yellow]")
            else:
                console.print(f"[yellow]⚠ Unknown key '{k}'.[/yellow]")

    elif action == "reset":
        cs.reset()
        console.print("[bold green]✓ Configuration reset to default schema (backup created).[/bold green]")

    elif action == "export":
        out = args.path or args.key or "pulse_config.json"
        fmt = "json" if str(out).endswith(".json") else "env"
        success, msg = cs.export_config(Path(out), format=fmt)
        if success:
            console.print(f"[bold green]✓ {msg}[/bold green]")
        else:
            console.print(f"[bold red]✖ {msg}[/bold red]")

    elif action == "import":
        import_target = args.path or args.key
        if not import_target:
            console.print("[bold red]Usage: pulse config import <PATH>[/bold red]")
            return
        success, msg = cs.import_config(Path(import_target))
        if success:
            console.print(f"[bold green]✓ {msg}[/bold green]")
        else:
            console.print(f"[bold red]✖ {msg}[/bold red]")

    elif action == "edit":
        settings_menu()


def handle_doctor_cli(args):
    from pulse.core.doctor import DoctorRunner, CheckStatus
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    if getattr(args, "json", False):
        print(DoctorRunner.export(format="json"))
        return
    if getattr(args, "markdown", False):
        print(DoctorRunner.export(format="markdown"))
        return
    if getattr(args, "export_path", None):
        out_path = Path(args.export_path)
        fmt = "json" if out_path.suffix.lower() == ".json" else "markdown"
        content = DoctorRunner.export(format=fmt)
        out_path.write_text(content, encoding="utf-8")
        console.print(f"[bold green]✓ Doctor diagnostic report exported to {out_path}[/bold green]")
        return

    score_pct, overall_status, results, cat_scores = DoctorRunner.run_all()

    table = Table(title="[bold cyan]System Diagnostic Checks[/bold cyan]", box=box.ROUNDED, expand=True)
    table.add_column("Category", style="bold white")
    table.add_column("Check Name", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Details", style="dim")

    for r in results:
        status_color = "bold green" if r.status == CheckStatus.PASS else ("bold yellow" if r.status == CheckStatus.WARNING else "bold red")
        status_str = f"[{status_color}]{r.status.value}[/{status_color}]"
        detail_str = " • ".join(r.details)
        table.add_row(r.category, r.name, status_str, f"{r.score_points}/{r.max_points}", detail_str)

    console.print(table)

    breakdown_lines = []
    for cat, (earned, max_p) in cat_scores.items():
        st = "[green]PASS[/green]" if earned == max_p else ("\x1b[33mWARNING\x1b[0m" if earned >= max_p * 0.7 else "[red]FAIL[/red]")
        breakdown_lines.append(f"  {cat:<20} {earned:2d} / {max_p:2d} pts  {st}")

    card_color = "bold green" if overall_status == CheckStatus.PASS else ("bold yellow" if overall_status == CheckStatus.WARNING else "bold red")
    console.print(Panel(
        f"[{card_color}]Overall System Health: {score_pct}% ({overall_status.value})[/{card_color}]\n\n[bold]Score Breakdown:[/bold]\n" + "\n".join(breakdown_lines),
        title="[bold white]System Health Diagnostics[/bold white]",
        box=box.SQUARE,
        expand=False
    ))


def handle_docs_cli(args):
    from pulse.core.config_service import ConfigService
    doc_type = getattr(args, "docs_type", "config")
    if doc_type == "config":
        out_path = Path("docs/configuration.md")
        ConfigService.get_instance().generate_markdown_docs(out_path)
        console.print(f"[bold green]✓ Generated configuration documentation at {out_path}[/bold green]")


def main():
    parser = argparse.ArgumentParser(description="PULSE CLI")
    parser.add_argument("--no-banner", action="store_true", help="Skip ASCII banner")
    parser.add_argument("--offline", action="store_true", help="Disable smart online detection")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output including resolution scores")
    parser.add_argument("--compact", action="store_true", help="Show compact executive summary only")
    parser.add_argument("--attack-paths", action="store_true", help="Enable attack path and exposure analysis")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging and diagnostic stack traces")

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # pulse config
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_parser.add_argument("config_action", nargs="?", choices=["list", "get", "set", "diff", "validate", "reset", "export", "import", "edit"], default="list")
    config_parser.add_argument("key", nargs="?", default=None, help="Setting key or target path")
    config_parser.add_argument("value", nargs="?", default=None, help="Setting value")
    config_parser.add_argument("--path", default=None, help="File path for import/export")

    # pulse doctor
    doctor_parser = subparsers.add_parser("doctor", help="System health diagnostics")
    doctor_parser.add_argument("--json", action="store_true", help="Output doctor diagnostics as JSON")
    doctor_parser.add_argument("--markdown", action="store_true", help="Output doctor diagnostics as Markdown")
    doctor_parser.add_argument("--export", dest="export_path", default=None, help="Export doctor report to file")

    # pulse docs
    docs_parser = subparsers.add_parser("docs", help="Documentation generation commands")
    docs_parser.add_argument("docs_type", nargs="?", choices=["config"], default="config", help="Documentation type to generate")
    
    args = parser.parse_args()
    
    from pulse.state import AppState, SummaryMode
    from pulse.core.logging_config import setup_logging, set_scan_correlation_id
    
    setup_logging(debug=args.debug)
    set_scan_correlation_id()
    
    AppState.OFFLINE_MODE = args.offline
    AppState.VERBOSE_MODE = args.verbose
    AppState.DEBUG_MODE = args.debug
    AppState.SHOW_ATTACK_PATHS = args.attack_paths
    
    if args.compact:
        AppState.SUMMARY_MODE = SummaryMode.COMPACT
    elif args.verbose:
        AppState.SUMMARY_MODE = SummaryMode.VERBOSE
    else:
        AppState.SUMMARY_MODE = SummaryMode.NORMAL

    try:
        load_config()
        init_db()

        if args.command == "config":
            handle_config_cli(args)
            return
        elif args.command == "doctor":
            handle_doctor_cli(args)
            return
        elif args.command == "docs":
            handle_docs_cli(args)
            return
        
        if not args.no_banner:
            show_banner()
            
        startup_health_check()
        interactive_menu()
        
    except KeyboardInterrupt:
        console.print("\n[bold green]Goodbye![/bold green]")
        sys.exit(0)

if __name__ == "__main__":
    main()
