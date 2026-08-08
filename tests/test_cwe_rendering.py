import pytest
from rich.console import Console
from datetime import datetime

from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.ui import print_findings_table, print_highest_risk_finding


def test_cwe_rendering_in_tables_and_panels(capsys):
    pkg = PackageInfo(name="django", version="3.2.0", ecosystem="python")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2021-31542",
        cvss_score=8.8,
        cvss_severity="HIGH",
        cwe="CWE-22",
        fix_version="3.2.2",
        source="OSV"
    )

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="4.0.0",
        packages_scanned=1,
        attack_surface_score=60,
        findings=[finding]
    )

    console = Console(width=160)
    print_findings_table(console, scan.findings)
    captured_table = capsys.readouterr().out

    assert "CWE" in captured_table
    assert "CWE-22" in captured_table

    print_highest_risk_finding(console, finding)
    captured_panel = capsys.readouterr().out

    assert "CWE Classification" in captured_panel
    assert "CWE-22" in captured_panel
