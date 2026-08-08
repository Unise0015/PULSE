from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.core.data_validator import (
    VulnerabilityDataValidator,
    FindingRejectReason
)

def test_data_validator_cve_id():
    valid, err = VulnerabilityDataValidator.validate_cve_id("CVE-2024-1234")
    assert valid is True
    assert err is None

    valid, err = VulnerabilityDataValidator.validate_cve_id("CVE-2024-1234567")
    assert valid is True

    valid, err = VulnerabilityDataValidator.validate_cve_id("INVALID-CVE-ID")
    assert valid is False
    assert err == FindingRejectReason.INVALID_CVE

    valid, err = VulnerabilityDataValidator.validate_cve_id(None)
    assert valid is False
    assert err == FindingRejectReason.INVALID_CVE


def test_data_validator_cvss_score():
    valid, err = VulnerabilityDataValidator.validate_cvss_score(7.5)
    assert valid is True
    assert err is None

    valid, err = VulnerabilityDataValidator.validate_cvss_score(0.0)
    assert valid is True

    valid, err = VulnerabilityDataValidator.validate_cvss_score(10.0)
    assert valid is True

    valid, err = VulnerabilityDataValidator.validate_cvss_score(11.5)
    assert valid is False
    assert err == FindingRejectReason.INVALID_CVSS

    valid, err = VulnerabilityDataValidator.validate_cvss_score(-1.0)
    assert valid is False
    assert err == FindingRejectReason.INVALID_CVSS


def test_data_validator_epss_score():
    valid, err = VulnerabilityDataValidator.validate_epss_score(0.45)
    assert valid is True
    assert err is None

    valid, err = VulnerabilityDataValidator.validate_epss_score(1.5)
    assert valid is False
    assert err == FindingRejectReason.INVALID_EPSS


def test_data_validator_cwe_id():
    valid, err = VulnerabilityDataValidator.validate_cwe_id("CWE-79")
    assert valid is True

    valid, err = VulnerabilityDataValidator.validate_cwe_id("CWE-89")
    assert valid is True

    valid, err = VulnerabilityDataValidator.validate_cwe_id("INVALID-CWE")
    assert valid is False
    assert err == FindingRejectReason.INVALID_CWE


def test_validate_finding_full():
    pkg = PackageInfo(name="requests", version="2.25.0", ecosystem="python")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-32681",
        cvss_score=7.5,
        cvss_severity="HIGH",
        epss_score=0.04,
        epss_percent="4%",
        kev_match=False,
        risk_heat_score=45,
        cwe="CWE-200",
        description="Information disclosure",
        fix_version="2.31.0",
        source="OSV",
        published_date="2023-05-26",
        last_modified_date="2023-06-01",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    )

    is_valid, warnings, rejections = VulnerabilityDataValidator.validate_finding(finding)
    assert is_valid is True
    assert len(rejections) == 0
