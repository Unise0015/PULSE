import pytest
from rich.console import Console
from datetime import datetime

from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.core.provider_health import provider_tracker, ProviderStatus
from pulse.ui import print_provider_observability


def test_provider_statistics_rendering(capsys):
    provider_tracker.reset()
    
    with provider_tracker.track("OSV") as health:
        health.records_requested = 10
        health.records_enriched = 10
        health.cache_hits = 8
        health.cache_misses = 2
        health.network_requests = 2

    with provider_tracker.track("NVD") as health:
        health.records_requested = 5
        health.records_enriched = 5
        health.cache_hits = 0
        health.cache_misses = 5
        health.network_requests = 5

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="4.0.0",
        packages_scanned=2,
        attack_surface_score=10,
        findings=[]
    )

    console = Console()
    print_provider_observability(console, scan)
    captured = capsys.readouterr().out

    assert "Provider Statistics" in captured
    assert "OSV" in captured
    assert "NVD" in captured
    assert "HEALTHY" in captured
    assert "Efficiency:" in captured
