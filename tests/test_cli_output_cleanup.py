import io
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch
from rich.console import Console

from pulse.domain.models import (
    ScanResult, VulnerabilityFinding, PackageInfo,
    TechnologyFingerprint, WebsiteAssessment, CorrelationStatus
)
from pulse.ui import clean_display_text, print_highest_risk_finding, print_website_assessment_summary
from pulse.services.package_service import PackageService
from pulse.services.website_service import WebsiteService
from pulse.scanner import ScannerOrchestrator


def test_clean_display_text_handles_raw_escapes():
    # Literal escaped newlines
    raw = "CVE-2020-11023\\nDescription Line 2"
    cleaned = clean_display_text(raw)
    assert "\\n" not in cleaned
    assert "CVE-2020-11023\nDescription Line 2" == cleaned

    # Literal windows escapes
    raw_win = "Line 1\\r\\nLine 2"
    cleaned_win = clean_display_text(raw_win)
    assert "\\r\\n" not in cleaned_win
    assert "Line 1\nLine 2" == cleaned_win

    # None and empty handling
    assert clean_display_text(None) == ""
    assert clean_display_text("") == ""


def test_package_service_output_no_redundant_messages():
    """PackageService uses a single transient progress spinner and does not leave duplicate Scanning messages."""
    console = Console(file=io.StringIO(), color_system=None)
    pkg = PackageInfo(name="django", version="3.2", ecosystem="Python")
    
    service = PackageService()
    result = service.run(console, [pkg], target_type="package", target_id="python:django")
    
    output = console.file.getvalue()
    # Should not leave "Scan completed" in permanent console output
    assert "Scan completed" not in output
    assert "Scanning..." not in output
    # Results should be intact
    assert result.packages_scanned == 1
    assert len(result.findings) > 0


@patch("pulse.website.website_fingerprint.WebsiteFingerprintAnalyzer.scan")
def test_website_service_output_no_redundant_completed_messages(mock_scan):
    """WebsiteService should not output 'Website analysis completed' or 'Fingerprinting Website:'."""
    console = Console(file=io.StringIO(), color_system=None)
    tech = TechnologyFingerprint(name="jQuery", version="1.7.2", category="Frontend Library", confidence=90)
    mock_scan.return_value = WebsiteAssessment(url="https://example.com", technologies=[tech])
    
    service = WebsiteService()
    scan_result = service.run(console, "https://example.com")
    output = console.file.getvalue()
    
    assert "Website analysis completed" not in output
    assert "Fingerprinting Website:" not in output
    assert scan_result.website_assessment is not None


def test_website_correlation_no_duplicate_provider_completed_messages():
    """Website technology correlation in normal mode should not print noisy provider completion messages."""
    console = Console(file=io.StringIO(), color_system=None)
    service = WebsiteService()
    
    # Mock assessment with jQuery 1.7.2 and confidence >= 40
    tech = TechnologyFingerprint(name="jQuery", version="1.7.2", category="Frontend Library", confidence=90)
    assessment = WebsiteAssessment(url="https://example.com", technologies=[tech])
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="localhost",
        tool_version="1.0",
        packages_scanned=0,
        attack_surface_score=0,
        website_assessment=assessment,
        target_type="website",
        target_id="https://example.com"
    )
    
    service.analyze_technologies(console, scan)
    output = console.file.getvalue()
    
    assert "OSV lookup completed" not in output
    assert "NVD Enrichment completed" not in output
    assert "CPE Correlation completed" not in output
    assert "Website analysis completed" not in output
    
    # Findings should be present and accurate
    assert len(scan.findings) >= 5
    cve_ids = {f.cve_id for f in scan.findings}
    assert "CVE-2020-11023" in cve_ids


@patch("pulse.vulnerability.nvd_provider.NVDProvider.enrich_findings")
@patch("pulse.vulnerability.threat_intel.EPSSProvider.enrich_findings")
@patch("pulse.vulnerability.threat_mapping.ThreatMapper.enrich_findings")
@patch("pulse.vulnerability.threat_intel.KEVProvider.enrich_findings")
@patch("pulse.vulnerability.exploit_intelligence.ExploitIntelligenceAnalyzer.enrich_findings")
def test_lookup_cve_no_redundant_completed_messages(mock_exploit, mock_kev, mock_threat, mock_epss, mock_nvd):
    """lookup_cve should not output 'Lookup completed' or 'Looking up details for ...'."""
    console = Console(file=io.StringIO(), color_system=None)
    orchestrator = ScannerOrchestrator()
    
    def fill_finding(findings):
        for f in findings:
            f.description = "Test vulnerability description"
            f.cvss_score = 7.5
            f.cvss_severity = "HIGH"
    
    mock_nvd.side_effect = fill_finding
    
    orchestrator.lookup_cve(console, "CVE-2020-11023")
    output = console.file.getvalue()
    
    assert "Lookup completed" not in output
    assert "Looking up details for" not in output
    assert "CVE-2020-11023" in output
    assert "Description" in output


def test_finding_rendering_no_literal_escape_sequences():
    """Highest risk finding panel must not render literal '\n' strings."""
    console = Console(file=io.StringIO(), color_system=None)
    pkg = PackageInfo(name="jquery", version="1.7.2", ecosystem="npm")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2020-11023",
        cvss_score=6.1,
        cvss_severity="MEDIUM",
        epss_score=0.05,
        epss_percent="85%",
        kev_match=False,
        risk_heat_score=65,
        description="Passing HTML from untrusted sources to jQuery\'s DOM manipulation methods."
    )
    
    print_highest_risk_finding(console, finding)
    output = console.file.getvalue()
    
    assert "\\n" not in output
    assert "CVE-2020-11023" in output
    assert "CVSS Score" in output
    assert "6.1" in output
