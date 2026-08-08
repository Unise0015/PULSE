import pytest
from pulse.domain.models import ScanResult, WebsiteAssessment, TechnologyFingerprint
from pulse.scanner import ScannerOrchestrator
from pulse.vulnerability.osv_provider import OSVProvider
from pulse.domain.models import PackageInfo
from datetime import datetime

def test_unsupported_technologies_filtered(capsys):
    scan = ScanResult(
        website_assessment=WebsiteAssessment(
            url="https://exams.keralauniversity.ac.in",
            technologies=[
                TechnologyFingerprint(name="apache", version="2.4.6", category="Web Server", confidence_score=90, detection_source="test", correlation_supported=False),
                TechnologyFingerprint(name="php", version="7.1.33", category="Runtime", confidence_score=90, detection_source="test", correlation_supported=False),
                TechnologyFingerprint(name="jquery", version="2.1.4", category="Frontend Library", confidence_score=90, detection_source="test", ecosystem="npm", correlation_supported=True)
            ],
            security_headers=[]
        ),
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=0,
        attack_surface_score=0,
        scan_duration_seconds=1.0
    )
    
    import rich.console
    console = rich.console.Console()
    
    orchestrator = ScannerOrchestrator()
    orchestrator.analyze_website_technologies(console, scan)
    
    # Packages_scanned should be 1 (jquery)
    assert scan.packages_scanned == 1
    
def test_all_unsupported_technologies_filtered(capsys):
    scan = ScanResult(
        website_assessment=WebsiteAssessment(
            url="https://wordpress.org",
            technologies=[
                TechnologyFingerprint(name="wordpress", version="7.x", category="CMS", confidence_score=95, detection_source="test", correlation_supported=False)
            ],
            security_headers=[]
        ),
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=0,
        attack_surface_score=0,
        scan_duration_seconds=1.0
    )
    
    import rich.console
    console = rich.console.Console()
    
    orchestrator = ScannerOrchestrator()
    orchestrator.analyze_website_technologies(console, scan)
    
    assert scan.packages_scanned == 0

def test_osv_defensive_validation():
    provider = OSVProvider()
    
    # Should skip
    res_php = provider.lookup_packages([PackageInfo(name="php", version="7.1.33", ecosystem="None")])
    assert len(res_php) == 0
    
    # Should attempt (return list, empty if none or hit cache)
    res_npm = provider.lookup_packages([PackageInfo(name="nonexistent-pkg-for-test", version="1.0.0", ecosystem="npm")])
    # The important part is that it doesn't crash with 400 when we test defensive validation
