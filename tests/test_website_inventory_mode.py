import pytest
from datetime import datetime
import json
from pulse.domain.models import ScanResult, WebsiteAssessment, TechnologyFingerprint, CorrelationStatus, FindingSourceType, TechnologyCategory, VulnerabilityFinding, PackageInfo
from pulse.scanner import ScannerOrchestrator
from pulse.ui import print_website_assessment_summary, print_technologies_view, print_top_attack_paths
from pulse.reporter import EnhancedJSONEncoder, export_json, export_sarif
from pulse.supply_chain.attack_paths import AttackPathAnalyzer
import rich.console

def test_initial_website_assessment_not_run():
    # Setup scan result representing initial target scan before correlation
    scan = ScanResult(
        website_assessment=WebsiteAssessment(
            url="https://www.keralauniversity.ac.in",
            technologies=[
                TechnologyFingerprint(
                    name="bootstrap",
                    version=None,
                    category=TechnologyCategory.UI_LIBRARY,
                    confidence=90,
                    correlation_supported=False
                ),
                TechnologyFingerprint(
                    name="jquery",
                    version="1.7.2",
                    category=TechnologyCategory.UI_LIBRARY,
                    confidence=95,
                    correlation_supported=True
                )
            ]
        ),
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="1.0",
        packages_scanned=0,
        attack_surface_score=0,
        scan_duration_seconds=1.0,
        target_type="website",
        target_id="https://www.keralauniversity.ac.in"
    )
    
    # 1. Initially correlation status must be NOT_RUN
    assert scan.website_assessment.correlation_status == CorrelationStatus.NOT_RUN
    assert scan.website_assessment.correlation_completed_at is None
    
    # 2. No website CVE findings should exist initially
    website_cves = [f for f in scan.findings if getattr(f, "source_type", None) == FindingSourceType.WEBSITE]
    assert len(website_cves) == 0
    
    # Test rendering initial view with a Dummy Console
    console = rich.console.Console(width=80)
    print_website_assessment_summary(console, scan)
    print_technologies_view(console, scan)

def test_website_correlation_success():
    scan = ScanResult(
        website_assessment=WebsiteAssessment(
            url="https://www.keralauniversity.ac.in",
            technologies=[
                TechnologyFingerprint(
                    name="jquery",
                    version="1.7.2",
                    category=TechnologyCategory.UI_LIBRARY,
                    confidence=95,
                    correlation_supported=True
                )
            ]
        ),
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="1.0",
        packages_scanned=0,
        attack_surface_score=0,
        scan_duration_seconds=1.0,
        target_type="website",
        target_id="https://www.keralauniversity.ac.in"
    )
    
    console = rich.console.Console()
    orchestrator = ScannerOrchestrator()
    
    # Run the correlation
    orchestrator.analyze_website_technologies(console, scan)
    
    # After correlation runs, status should be COMPLETED, PARTIAL or FAILED
    # and completed timestamp should be set.
    assert scan.website_assessment.correlation_status in (CorrelationStatus.COMPLETED, CorrelationStatus.PARTIAL, CorrelationStatus.FAILED)
    assert scan.website_assessment.correlation_completed_at is not None
    
    # Verify that metrics were incremented
    total_processed = scan.website_assessment.correlated_technologies + scan.website_assessment.failed_technologies
    assert total_processed >= 1
    
    # Render view after correlation
    print_website_assessment_summary(console, scan)
    print_technologies_view(console, scan)

def test_attack_paths_source_type():
    # Setup scan with a website vulnerability finding
    finding = VulnerabilityFinding(
        package=PackageInfo(name="jquery", version="1.7.2", ecosystem="npm"),
        cve_id="CVE-2012-6708",
        cvss_score=6.1,
        cvss_severity="MEDIUM",
        epss_score=0.15,
        epss_percent="15%",
        kev_match=False,
        risk_heat_score=60,
        description="Cross-site scripting (XSS) in jQuery before 1.9.0",
        fix_version="1.9.0",
        source="NVD",
        published_date="2012-06-01",
        last_modified_date="2012-06-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2012-6708",
        source_type=FindingSourceType.WEBSITE,
        source_asset="jquery"
    )
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=60,
        scan_duration_seconds=1.0,
        findings=[finding],
        target_type="website",
        target_id="https://www.keralauniversity.ac.in"
    )
    
    # Run attack path analyzer
    AttackPathAnalyzer.generate(scan)
    
    assert len(scan.attack_paths) == 1
    # Verify that the generated attack path has source_type = website
    assert scan.attack_paths[0].source_type == FindingSourceType.WEBSITE
    
    console = rich.console.Console()
    print_top_attack_paths(console, scan)

def test_enhanced_json_encoder_enum_serialization():
    # Setup test data with Enums and datetimes
    wa = WebsiteAssessment(
        url="https://www.keralauniversity.ac.in",
        correlation_status=CorrelationStatus.PARTIAL,
        correlation_completed_at=datetime(2026, 6, 24, 16, 5)
    )
    
    # Check that serialization converts Enum to value
    serialized_status = json.loads(json.dumps(wa.correlation_status, cls=EnhancedJSONEncoder))
    assert serialized_status == "Partial"
    
    # Test full serialization structure
    dumped = json.loads(json.dumps(wa, cls=EnhancedJSONEncoder))
    assert dumped["correlation_status"] == "Partial"
    assert dumped["correlation_completed_at"] == "2026-06-24T16:05:00"
