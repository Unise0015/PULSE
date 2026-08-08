import pytest
from rich.console import Console
from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.ui import render_cve_details


def test_cve_details_rendering(capsys):
    pkg = PackageInfo(name="requests", version="2.25.0", ecosystem="python")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-32681",
        cvss_score=7.5,
        cvss_severity="HIGH",
        cwe="CWE-200",
        description="Requests leaks Proxy-Authorization headers when redirected.",
        fix_version="2.31.0",
        source="OSV"
    )

    console = Console()
    render_cve_details(console, finding)
    captured = capsys.readouterr().out

    assert "Vulnerability Detail Inspection — CVE-2023-32681" in captured
    assert "CVE ID" in captured
    assert "CVE-2023-32681" in captured
    assert "CWE-200" in captured
    assert "Remediation Guidance" in captured
    assert "2.31.0" in captured
