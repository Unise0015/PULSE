import pytest
from pulse.vulnerability.policy import ScanPolicy, PolicyConfig
from pulse.domain.models import VulnerabilityFinding, PackageInfo
from pulse.config import set_setting

def test_policy_engine_informational_non_blocking():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="npm")
    finding = VulnerabilityFinding(
        cve_id="CVE-2024-0001",
        package=pkg,
        cvss_score=0.0,
        cvss_severity="INFORMATIONAL",
        description="Informational note",
        fix_version="1.1"
    )
    assert not ScanPolicy.is_blocking(finding)

def test_policy_engine_cvss_zero_non_blocking():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="npm")
    finding = VulnerabilityFinding(
        cve_id="CVE-2024-0002",
        package=pkg,
        cvss_score=0.0,
        cvss_severity="UNKNOWN",
        kev_match=False,
        description="Zero score",
        fix_version="1.1"
    )
    assert not ScanPolicy.is_blocking(finding)

def test_policy_engine_kev_override():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="npm")
    finding = VulnerabilityFinding(
        cve_id="CVE-2024-0003",
        package=pkg,
        cvss_score=2.0,
        cvss_severity="LOW",
        kev_match=True,
        description="KEV listed",
        fix_version="1.1"
    )
    set_setting("PULSE_MIN_SEVERITY", "HIGH")
    set_setting("PULSE_KEV_OVERRIDE", "True")
    assert ScanPolicy.is_blocking(finding)

def test_policy_engine_epss_threshold():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="npm")
    finding = VulnerabilityFinding(
        cve_id="CVE-2024-0004",
        package=pkg,
        cvss_score=3.0,
        cvss_severity="LOW",
        epss_score=0.5,
        kev_match=False,
        description="High EPSS",
        fix_version="1.1"
    )
    set_setting("PULSE_MIN_SEVERITY", "HIGH")
    set_setting("PULSE_EPSS_THRESHOLD", "0.1")
    assert ScanPolicy.is_blocking(finding)
