import pytest
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo

def test_highest_severity_selection_critical():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="pypi")
    f_crit = VulnerabilityFinding(cve_id="CVE-1", package=pkg, cvss_score=9.8, cvss_severity="CRITICAL")
    f_high = VulnerabilityFinding(cve_id="CVE-2", package=pkg, cvss_score=7.5, cvss_severity="HIGH")
    
    scan = ScanResult(timestamp=None, hostname="test", tool_version="1.0", packages_scanned=1, attack_surface_score=50, findings=[f_crit, f_high])
    
    severities = [f.cvss_severity.upper() for f in scan.findings if getattr(f, "cvss_severity", None)]
    assert "CRITICAL" in severities
    filtered = [f for f in scan.findings if f.cvss_severity.upper() == "CRITICAL"]
    assert len(filtered) == 1
    assert filtered[0].cve_id == "CVE-1"

def test_highest_severity_selection_high_fallback():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="pypi")
    f_high = VulnerabilityFinding(cve_id="CVE-2", package=pkg, cvss_score=7.5, cvss_severity="HIGH")
    f_med = VulnerabilityFinding(cve_id="CVE-3", package=pkg, cvss_score=5.0, cvss_severity="MEDIUM")
    
    scan = ScanResult(timestamp=None, hostname="test", tool_version="1.0", packages_scanned=1, attack_surface_score=50, findings=[f_high, f_med])
    
    severities = [f.cvss_severity.upper() for f in scan.findings if getattr(f, "cvss_severity", None)]
    assert "CRITICAL" not in severities
    assert "HIGH" in severities
    filtered = [f for f in scan.findings if f.cvss_severity.upper() == "HIGH"]
    assert len(filtered) == 1
    assert filtered[0].cve_id == "CVE-2"

def test_highest_severity_selection_medium_fallback():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="pypi")
    f_med = VulnerabilityFinding(cve_id="CVE-3", package=pkg, cvss_score=5.0, cvss_severity="MEDIUM")
    
    scan = ScanResult(timestamp=None, hostname="test", tool_version="1.0", packages_scanned=1, attack_surface_score=50, findings=[f_med])
    
    severities = [f.cvss_severity.upper() for f in scan.findings if getattr(f, "cvss_severity", None)]
    assert "CRITICAL" not in severities
    assert "HIGH" not in severities
    assert "MEDIUM" in severities
    filtered = [f for f in scan.findings if f.cvss_severity.upper() == "MEDIUM"]
    assert len(filtered) == 1
    assert filtered[0].cve_id == "CVE-3"
