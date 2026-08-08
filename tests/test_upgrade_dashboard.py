import pytest
from rich.console import Console
from datetime import datetime

from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.ui import print_remediation_table


def test_upgrade_dashboard_columns_rendering(capsys):
    pkg = PackageInfo(name="express", version="4.16.0", ecosystem="npm")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2024-9999",
        cvss_score=8.5,
        cvss_severity="HIGH",
        fix_version="4.19.2",
        source="OSV"
    )

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="4.0.0",
        packages_scanned=1,
        attack_surface_score=50,
        findings=[finding]
    )

    console = Console(width=160)
    print_remediation_table(console, scan)
    captured = capsys.readouterr().out

    assert "Package Upgrade Dashboard" in captured
    assert "Current" in captured
    assert "Recommended" in captured
    assert "Latest Stable" in captured
    assert "Verification" in captured
    assert "Migration Risk" in captured
    assert "Security Gap" in captured
    assert "express" in captured
    assert "Remediation Strategy — express" in captured
