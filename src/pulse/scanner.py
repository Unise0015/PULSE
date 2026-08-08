from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.vulnerability.nvd_provider import NVDProvider
from pulse.vulnerability.threat_intel import EPSSProvider, KEVProvider
from pulse.vulnerability.threat_mapping import ThreatMapper
from pulse.vulnerability.exploit_intelligence import ExploitIntelligenceAnalyzer

class ScannerOrchestrator:
    """Coordinates the scan pipeline: Discovery -> OSV -> NVD -> EPSS -> KEV.
    
    This class now acts as a facade, delegating orchestration to specialized service classes.
    """
    
    def __init__(self):
        from pulse.services.scan_service import ScanService
        from pulse.services.package_service import PackageService
        from pulse.services.website_service import WebsiteService
        self.scan_service = ScanService()
        self.package_service = PackageService()
        self.website_service = WebsiteService()

    def run_auto_discover_scan(self, console):
        return self.scan_service.run(console)

    def run_targeted_scan(self, console, packages, target_type: str = "global", target_id: str = "global"):
        return self.package_service.run(console, packages, target_type, target_id)

    def run_website_scan(self, console, url: str):
        return self.website_service.run(console, url)

    def analyze_website_technologies(self, console, scan):
        return self.website_service.analyze_technologies(console, scan)

    def get_historical_scan(self, scan_id: int):
        from pulse.history import HistoryService
        from pulse.vulnerability.threat_mapping import ThreatMapper
        history = HistoryService()
        scan = history.get_scan_by_id(scan_id)
        if scan:
            if scan.target_type == "website" and getattr(scan, "website_assessment", None):
                scan._reconstructing = True
                from pulse.services.website_service import WebsiteService
                class DummyConsole:
                    def print(self, *args, **kwargs):
                        pass
                try:
                    ws = WebsiteService()
                    ws.analyze_technologies(DummyConsole(), scan)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).error(f"Failed to resolve historical website findings: {e}")
            mapper = ThreatMapper()
            mapper.enrich_findings(scan.findings)
        return scan


    def lookup_cve(self, console, cve_id: str):
        console.print(f"\n[bold]Looking up details for {cve_id}...[/bold]")
        
        # Construct a dummy finding to pass through NVD/EPSS/KEV providers.
        dummy_pkg = PackageInfo(name="unknown", version="unknown", ecosystem="unknown")
        finding = VulnerabilityFinding(
            package=dummy_pkg,
            cve_id=cve_id,
            cvss_score=0.0,
            cvss_severity="UNKNOWN",
            epss_score=0.0,
            epss_percent="0%",
            kev_match=False,
            risk_heat_score=0,
            description="",
            fix_version=None,
            source="lookup",
            published_date=None,
            last_modified_date=None,
            nvd_url=""
        )
        
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            task = progress.add_task("[yellow]Fetching from NVD...[/yellow]", total=None)
            nvd_provider = NVDProvider()
            nvd_provider.enrich_findings([finding])
            
            progress.update(task, description="[yellow]Fetching from EPSS...[/yellow]")
            epss_provider = EPSSProvider()
            epss_provider.enrich_findings([finding])
            
            progress.update(task, description="[yellow]Mapping MITRE ATT&CK...[/yellow]")
            threat_mapper = ThreatMapper()
            threat_mapper.enrich_findings([finding])
            
            progress.update(task, description="[yellow]Checking KEV...[/yellow]")
            kev_provider = KEVProvider()
            kev_provider.enrich_findings([finding])
            
            # Enrich with Exploit Intelligence
            ExploitIntelligenceAnalyzer.enrich_findings([finding])
            
            progress.update(task, completed=1, description="[green]Lookup completed[/green]")
            
        if not finding.description:
            console.print(f"[red]Could not find details for {cve_id} in NVD.[/red]")
            return

        text = Text()
        text.append("Description\n", style="bold cyan")
        text.append(finding.description + "\n\n")
        
        if finding.published_date:
            text.append("Published Date\n", style="bold cyan")
            text.append(f"{finding.published_date}\n\n")
            
        if finding.last_modified_date:
            text.append("Last Modified Date\n", style="bold cyan")
            text.append(f"{finding.last_modified_date}\n\n")
            
        if finding.cwe:
            text.append("CWE\n", style="bold cyan")
            text.append(f"{finding.cwe}\n\n")
        
        text.append("CVSS Score\n", style="bold cyan")
        cvss_color = "red" if finding.cvss_score >= 9.0 else "yellow"
        text.append(f"{finding.cvss_score} ({finding.cvss_severity})\n\n", style=cvss_color)
        
        if finding.cvss_vector:
            text.append("CVSS Vector\n", style="bold cyan")
            text.append(f"{finding.cvss_vector}\n\n")
        
        text.append("EPSS\n", style="bold cyan")
        text.append(f"{finding.epss_percent} (Score: {finding.epss_score})\n\n")
        
        if finding.attack_techniques:
            text.append("MITRE ATT&CK\n", style="bold cyan")
            for t in finding.attack_techniques:
                text.append(f"{t.technique_id} - {t.technique_name} ", style="bold red")
                text.append(f"({t.tactic})\n", style="dim")
            text.append("\n")
        
        text.append("CISA KEV\n", style="bold cyan")
        kev_str = "Yes" if finding.kev_match else "No"
        kev_color = "red bold" if finding.kev_match else "green"
        text.append(f"{kev_str}\n\n", style=kev_color)

        poc_val = "Yes" if (finding.exploit_intelligence and finding.exploit_intelligence.public_poc) else "No"
        text.append("Public PoC\n", style="bold cyan")
        text.append(f"{poc_val}\n\n")
        if finding.exploit_intelligence and finding.exploit_intelligence.poc_source:
            text.append("PoC Source\n", style="bold cyan")
            text.append(f"{finding.exploit_intelligence.poc_source}\n\n")
        maturity_val = finding.exploit_intelligence.exploit_maturity if finding.exploit_intelligence else "No Public PoC Identified"
        text.append("Exploit Maturity\n", style="bold cyan")
        text.append(f"{maturity_val}\n\n")

        if finding.nvd_url:
            text.append("NVD URL\n", style="bold cyan")
            text.append(f"{finding.nvd_url}\n\n")
            
        if finding.reference_url:
            text.append("References\n", style="bold cyan")
            text.append(f"{finding.reference_url}\n\n")

        # Affected Package conditionally displayed
        if finding.package.name != "unknown":
            text.append("Affected Package\n", style="bold cyan")
            text.append(f"{finding.package.name}\n\n")
            
            text.append("Affected Versions\n", style="bold cyan")
            text.append(f"{finding.package.version}\n\n")
            
            if finding.fix_version:
                text.append("Fixed Version\n", style="bold cyan")
                text.append(f"{finding.fix_version}\n\n")
                
        # Recommended Action conditionally
        if finding.fix_version and finding.package.name != "unknown":
            text.append("Recommended Action\n", style="bold cyan")
            text.append(f"Upgrade {finding.package.name} to {finding.fix_version}\n")

        console.print(Panel(text, title=f"CVE Details: {cve_id}", border_style="blue", padding=(1, 2)))
