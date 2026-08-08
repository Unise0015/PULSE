import pytest
from rich.console import Console
from pulse.domain.models import ScanResult, VulnerabilityFinding, SupplyChainMetrics, AttackPath
from pulse.state import AppState, SummaryMode
from pulse.ui import (
    print_security_summary, print_priority_summary, print_threat_summary,
    print_supply_chain_summary, print_attack_paths, print_trend_summary
)
from pulse.cli import post_scan_render
import io

@pytest.fixture
def mock_scan():
    from unittest.mock import MagicMock
    mock_pkg = MagicMock()
    mock_pkg.name = "test_pkg"
    mock_pkg.ecosystem = "npm"
    mock_pkg.version = "1.0.0"
    mock_pkg.version_metadata = None
    finding = VulnerabilityFinding(
        cve_id="CVE-2023-1234",
        package=mock_pkg,
        description="Test vuln",
        cvss_severity="HIGH",
        risk_heat_score=85,
        kev_match=True,
        cvss_score=8.5,
        epss_score=0.1,
        epss_percent=10.0,
        fix_version="1.0",
        source="mock",
        published_date=None,
        last_modified_date=None,
        nvd_url="mock"
    )
    
    scan = ScanResult(
        timestamp=None,
        hostname="test",
        tool_version="1.0",
        packages_scanned=105,
        attack_surface_score=27,
        scan_duration_seconds=1.0,
        findings=[finding],
        detected_ecosystems=["npm", "pypi"],
        target_type="project",
        target_id="test",
        target_fingerprint="abc"
    )
    # Mock attack technique
    class Tech:
        technique_id = "T1190"
        tactic = "Initial Access"
    finding.attack_techniques = [Tech()]

    # Mock Supply Chain
    scan.supply_chain_metrics = SupplyChainMetrics(
        direct_count=50,
        transitive_count=55,
        vulnerable_direct=5,
        vulnerable_transitive=7,
        max_depth=4
    )
    
    # Mock Attack Path
    path = AttackPath(
        package_name="test",
        package_version="1.0",
        cve_id="CVE-2023-1234",
        cwe=None,
        attack_techniques=[],
        attack_tactics=[],
        cvss_score=8.5,
        epss_score=0.1,
        kev_match=True,
        risk_score=90,
        exposure_score=95
    )
    scan.attack_paths = [path]
    return scan

@pytest.fixture
def console_capture():
    # Use an in-memory string IO to capture Rich console output
    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=120)
    return console, output

def test_default_scan_output(mock_scan, console_capture):
    console, output = console_capture
    AppState.SUMMARY_MODE = SummaryMode.NORMAL
    AppState.SHOW_ATTACK_PATHS = False
    
    post_scan_render(console, mock_scan)
    
    out_text = output.getvalue()
    assert "Security Summary" in out_text
    assert "Top Priorities" not in out_text
    
    # Excluded in NORMAL mode
    assert "Trend Analysis" not in out_text
    assert "Threat Intelligence" not in out_text
    assert "Supply Chain Analysis" not in out_text
    assert "Exposure Metrics" not in out_text

def test_verbose_scan_output(mock_scan, console_capture):
    console, output = console_capture
    AppState.SUMMARY_MODE = SummaryMode.VERBOSE
    AppState.SHOW_ATTACK_PATHS = False
    
    post_scan_render(console, mock_scan)
    
    out_text = output.getvalue()
    assert "Security Summary" in out_text
    assert "Top Priorities" not in out_text
    assert "Trend Analysis" in out_text
    assert "Threat Intelligence" in out_text
    assert "Supply Chain Analysis" in out_text
    
    # Excluded from VERBOSE mode unless explicitly requested
    assert "Exposure Metrics" not in out_text

def test_attack_paths_output(mock_scan, console_capture):
    console, output = console_capture
    AppState.SUMMARY_MODE = SummaryMode.NORMAL
    AppState.SHOW_ATTACK_PATHS = True
    
    post_scan_render(console, mock_scan)
    
    out_text = output.getvalue()
    assert "Exposure Metrics" in out_text
    assert "Attack Paths Identified" in out_text

def test_attack_paths_not_rendered_in_verbose_mode(mock_scan, console_capture):
    console, output = console_capture
    AppState.SUMMARY_MODE = SummaryMode.VERBOSE
    AppState.SHOW_ATTACK_PATHS = False
    
    post_scan_render(console, mock_scan)
    
    out_text = output.getvalue()
    assert "Exposure Metrics" not in out_text
    assert "Attack Paths Identified" not in out_text

def test_compact_mode(mock_scan, console_capture):
    console, output = console_capture
    AppState.SUMMARY_MODE = SummaryMode.COMPACT
    AppState.SHOW_ATTACK_PATHS = False
    
    post_scan_render(console, mock_scan)
    
    out_text = output.getvalue()
    assert "Security Summary" in out_text
    assert "Top Priorities" not in out_text
    assert "Threat Intelligence" not in out_text
    assert "Trend Analysis" not in out_text

def test_no_kev_matches_hides_section(mock_scan, console_capture):
    console, output = console_capture
    mock_scan.findings[0].kev_match = False
    AppState.SUMMARY_MODE = SummaryMode.VERBOSE
    
    print_threat_summary(console, mock_scan)
    
    out_text = output.getvalue()
    assert "KEV Matches" not in out_text
    # Still shows ATT&CK because ATT&CK techniques are present
    assert "MITRE ATT&CK" in out_text

def test_single_ecosystem_hides_section(mock_scan, console_capture):
    console, output = console_capture
    mock_scan.detected_ecosystems = ["npm"]
    AppState.SUMMARY_MODE = SummaryMode.NORMAL
    
    print_security_summary(console, mock_scan)
    
    out_text = output.getvalue()
    assert "Ecosystems" not in out_text
