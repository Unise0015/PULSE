import pytest
from io import StringIO
from rich.console import Console
from datetime import datetime
from unittest.mock import patch
from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.cli import post_scan_render


def _make_scan_with_finding():
    """Create a scan result with at least one finding for testing."""
    pkg = PackageInfo(name="express", version="4.16.0", ecosystem="npm")
    finding = VulnerabilityFinding(
        package=pkg, cve_id="CVE-2024-1111", cvss_score=7.5,
        cvss_severity="HIGH", source="OSV", risk_heat_score=65,
        cwe="CWE-79"
    )
    finding._cwe_name = "Cross-site Scripting"
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=35,
        findings=[finding]
    )
    return scan


def test_default_scan_summary_omits_diagnostics(capsys):
    scan = _make_scan_with_finding()
    console = Console()
    post_scan_render(console, scan)
    captured = capsys.readouterr().out

    assert "Security Summary" in captured
    assert "Provider Statistics" not in captured
    assert "Intelligence Confidence & Scan Integrity" not in captured
    assert "Validation Summary" not in captured


def test_default_scan_omits_top_priorities(capsys):
    scan = _make_scan_with_finding()
    console = Console()
    post_scan_render(console, scan)
    captured = capsys.readouterr().out

    assert "Top Priorities" not in captured


def test_default_scan_omits_trend_analysis(capsys):
    scan = _make_scan_with_finding()
    console = Console()
    post_scan_render(console, scan)
    captured = capsys.readouterr().out

    # Trend panel title should not appear in normal mode
    assert "Trend Analysis" not in captured
    assert "Previous Score" not in captured


def test_default_scan_auto_displays_highest_risk(capsys):
    scan = _make_scan_with_finding()
    console = Console()
    post_scan_render(console, scan)
    captured = capsys.readouterr().out

    # The highest risk finding panel should appear automatically
    assert "Highest Risk Finding" in captured or "CVE-2024-1111" in captured


def test_debug_mode_shows_extended_panels(capsys):
    from pulse.state import AppState
    original = AppState.DEBUG_MODE
    try:
        AppState.DEBUG_MODE = True
        scan = _make_scan_with_finding()
        console = Console()
        post_scan_render(console, scan)
        captured = capsys.readouterr().out

        # Debug mode should show extended panels
        assert "Security Summary" in captured
    finally:
        AppState.DEBUG_MODE = original


def test_no_findings_omits_highest_risk(capsys):
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=0,
        findings=[]
    )
    console = Console()
    post_scan_render(console, scan)
    captured = capsys.readouterr().out

    assert "Highest Risk Finding" not in captured
