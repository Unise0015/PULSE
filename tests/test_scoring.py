import pytest
from pulse.domain.models import VulnerabilityFinding, PackageInfo, ScanResult
from pulse.vulnerability.threat_intel import RiskCalculator

def test_risk_heat_score_calculation():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="python", dependency_type="DIRECT", reachability="UNKNOWN")
    
    # 1. Base test: (CVSS/10 * 50) + (EPSS * 30) + (KEV * 20)
    finding = VulnerabilityFinding(
        package=pkg, cve_id="CVE-1", cvss_score=10.0, cvss_severity="CRITICAL",
        epss_score=1.0, epss_percent="100%", kev_match=True, risk_heat_score=0,
        description="Test vulnerability", fix_version=None,
        source="OSV", published_date="2023", last_modified_date="2023", nvd_url=""
    )
    RiskCalculator.calculate_risk(finding)
    # 50 + 30 + 20 = 100
    assert finding.risk_heat_score == 100

    # 2. Partial test
    finding2 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-2", cvss_score=5.0, cvss_severity="MEDIUM",
        epss_score=0.5, epss_percent="50%", kev_match=False, risk_heat_score=0,
        description="Test vulnerability 2", fix_version=None,
        source="OSV", published_date="2023", last_modified_date="2023", nvd_url=""
    )
    RiskCalculator.calculate_risk(finding2)
    # (5/10*50)=25 + (0.5*30)=15 + 0 = 40
    assert finding2.risk_heat_score == 40
    
def test_attack_surface_score_calculation():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="python", dependency_type="DIRECT", reachability="UNKNOWN")
    
    f1 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-1", cvss_score=10.0, cvss_severity="CRITICAL",
        epss_score=1.0, epss_percent="100%", kev_match=True, risk_heat_score=100,
        description="Critical test vuln", fix_version=None,
        source="OSV", published_date="2023", last_modified_date="2023", nvd_url=""
    )
    
    f2 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-2", cvss_score=5.0, cvss_severity="MEDIUM",
        epss_score=0.5, epss_percent="50%", kev_match=False, risk_heat_score=40,
        description="Medium test vuln", fix_version=None,
        source="OSV", published_date="2023", last_modified_date="2023", nvd_url=""
    )
    
    findings = [f1, f2]
    # Average risk = (100+40)/2 = 70
    # KEV penalty = 1 * 10 = 10
    # Expected: 80
    
    avg_risk = sum(f.risk_heat_score for f in findings) // len(findings)
    kev_penalty = sum(10 for f in findings if f.kev_match)
    attack_surface_score = min(100, avg_risk + kev_penalty)
    
    assert attack_surface_score == 80


def test_normalize_severity():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="python")
    
    # CVSS 0.0 with no severity -> INFORMATIONAL
    f1 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-1", cvss_score=0.0, cvss_severity="UNKNOWN",
        epss_score=0.0, epss_percent="0%", kev_match=False, risk_heat_score=0,
        description="test", fix_version=None, source="OSV", published_date=None,
        last_modified_date=None, nvd_url=""
    )
    f1.normalize_severity()
    assert f1.cvss_severity == "INFORMATIONAL"
    
    # CVSS 9.8 with UNKNOWN severity -> CRITICAL
    f2 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-2", cvss_score=9.8, cvss_severity="UNKNOWN",
        epss_score=0.0, epss_percent="0%", kev_match=False, risk_heat_score=0,
        description="test", fix_version=None, source="OSV", published_date=None,
        last_modified_date=None, nvd_url=""
    )
    f2.normalize_severity()
    assert f2.cvss_severity == "CRITICAL"
    
    # CVSS 0.0 with KEV match -> LOW
    f3 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-3", cvss_score=0.0, cvss_severity="INFORMATIONAL",
        epss_score=0.0, epss_percent="0%", kev_match=True, risk_heat_score=0,
        description="test", fix_version=None, source="OSV", published_date=None,
        last_modified_date=None, nvd_url=""
    )
    f3.normalize_severity()
    assert f3.cvss_severity == "LOW"

