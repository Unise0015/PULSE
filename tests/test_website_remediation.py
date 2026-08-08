import pytest
from pulse.domain.models import VulnerabilityFinding, PackageInfo
from pulse.website.remediation import get_upgrade_recommendation

def test_remediation_no_findings():
    # If there are no findings, suggest a generic update path
    rec = get_upgrade_recommendation("nginx", "1.20.0", [])
    assert rec is not None
    assert rec.minimum_safe_version is None
    assert "No specific fix version identified" in rec.rationale
    assert "Nginx" in rec.rationale

def test_remediation_with_fix_versions():
    pkg = PackageInfo(name="nginx", version="1.20.0", ecosystem="website")
    
    f1 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-1", cvss_score=5.0, cvss_severity="MEDIUM",
        epss_score=0.1, epss_percent="10%", kev_match=False, risk_heat_score=50,
        description="test", fix_version="1.20.1", source="test", published_date=None,
        last_modified_date=None, nvd_url=""
    )
    f2 = VulnerabilityFinding(
        package=pkg, cve_id="CVE-2", cvss_score=6.0, cvss_severity="MEDIUM",
        epss_score=0.1, epss_percent="10%", kev_match=False, risk_heat_score=60,
        description="test", fix_version="1.20.2", source="test", published_date=None,
        last_modified_date=None, nvd_url=""
    )

    # Sorts versions and recommends the highest fix version (1.20.2)
    rec = get_upgrade_recommendation("nginx", "1.20.0", [f1, f2])
    assert rec is not None
    assert rec.minimum_safe_version == "1.20.2"
    assert rec.latest_security_fix == "1.20.2"
    assert "Upgrade to version 1.20.2 or higher" in rec.rationale

def test_remediation_invalid_inputs():
    # Invalid technology
    rec = get_upgrade_recommendation("nonexistent-tech", "1.0", [])
    assert rec is None

    # Missing current version
    rec = get_upgrade_recommendation("nginx", None, [])
    assert rec is None
