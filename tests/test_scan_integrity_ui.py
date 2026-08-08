import pytest
from rich.console import Console
from datetime import datetime

from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.core.provider_health import provider_tracker, ProviderStatus
from pulse.ui import print_provider_observability


def test_scan_integrity_reasons_rendering(capsys):
    provider_tracker.reset()
    
    # Simulate a provider failure causing MEDIUM or LOW integrity
    with provider_tracker.track("NVD") as health:
        health.status = ProviderStatus.ERROR
        health.warnings.append("NVD Service Unavailable (503)")

    pkg = PackageInfo(name="demo", version="1.0", ecosystem="python")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2026-1001",
        cvss_score=0.0, # Missing CVSS score triggers validation warning
        cvss_severity="UNKNOWN",
        source="NVD"
    )

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="4.0.0",
        packages_scanned=1,
        attack_surface_score=20,
        findings=[finding]
    )

    console = Console()
    print_provider_observability(console, scan)
    captured = capsys.readouterr().out

    assert "Intelligence Confidence & Scan Integrity" in captured
    assert "Scan Integrity: LOW" in captured or "Scan Integrity: MEDIUM" in captured
    assert "Contributing Factors:" in captured
