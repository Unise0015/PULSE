import pytest
from pulse.domain.data_validation import VulnerabilityDataValidator
from pulse.domain.models import VulnerabilityFinding, PackageInfo

def test_validate_cve_format():
    assert VulnerabilityDataValidator.validate_cve_format("CVE-2024-12345") is True
    assert VulnerabilityDataValidator.validate_cve_format("CVE-1999-0001") is True
    assert VulnerabilityDataValidator.validate_cve_format("CVE-ABC-123") is False
    assert VulnerabilityDataValidator.validate_cve_format("GHSA-1234") is False
    assert VulnerabilityDataValidator.validate_cve_format("") is False

def test_validate_cvss():
    assert VulnerabilityDataValidator.validate_cvss(5.5) == 5.5
    assert VulnerabilityDataValidator.validate_cvss(0.0) == 0.0
    assert VulnerabilityDataValidator.validate_cvss(10.0) == 10.0
    assert VulnerabilityDataValidator.validate_cvss(11.0) is None
    assert VulnerabilityDataValidator.validate_cvss(-1.0) is None

def test_validate_epss():
    assert VulnerabilityDataValidator.validate_epss(0.5) == 0.5
    assert VulnerabilityDataValidator.validate_epss(0.0) == 0.0
    assert VulnerabilityDataValidator.validate_epss(1.0) == 1.0
    assert VulnerabilityDataValidator.validate_epss(1.5) is None
    assert VulnerabilityDataValidator.validate_epss(-0.1) is None

def test_validate_osv_record():
    valid = {"id": "CVE-2022-1234", "summary": "Valid issue", "details": "Buffer overflow"}
    rejected = {"id": "CVE-2022-1235", "summary": "** REJECTED **"}
    reserved = {"id": "CVE-2022-1236", "details": "This candidate has been ** RESERVED **"}
    malformed = {"id": "CVE-ABC", "summary": "Bad"}
    
    assert VulnerabilityDataValidator.validate_osv_record(valid) is True
    assert VulnerabilityDataValidator.validate_osv_record(rejected) is False
    assert VulnerabilityDataValidator.validate_osv_record(reserved) is False
    assert VulnerabilityDataValidator.validate_osv_record(malformed) is False

def test_validate_nvd_record():
    valid = {"cve": {"id": "CVE-2022-1234", "vulnStatus": "Modified"}}
    rejected = {"cve": {"id": "CVE-2022-1235", "vulnStatus": "Rejected"}}
    malformed = {"cve": {"id": "CVE-ABC"}}
    
    assert VulnerabilityDataValidator.validate_nvd_record(valid) is True
    assert VulnerabilityDataValidator.validate_nvd_record(rejected) is False
    assert VulnerabilityDataValidator.validate_nvd_record(malformed) is False

def test_deduplicate_findings():
    pkg = PackageInfo("requests", "2.28.0", "PyPI")
    findings = [
        VulnerabilityFinding(package=pkg, cve_id="CVE-2022-1111", cvss_score=5.0, cvss_severity="MEDIUM", source="A", epss_score=0.0, epss_percent="0%", kev_match=False, risk_heat_score=0, description="desc", fix_version=None, published_date=None, last_modified_date=None, nvd_url=""),
        VulnerabilityFinding(package=pkg, cve_id="CVE-2022-1111", cvss_score=6.0, cvss_severity="MEDIUM", source="B", epss_score=0.0, epss_percent="0%", kev_match=False, risk_heat_score=0, description="desc", fix_version=None, published_date=None, last_modified_date=None, nvd_url=""), # Duplicate
        VulnerabilityFinding(package=pkg, cve_id="CVE-2022-2222", cvss_score=9.0, cvss_severity="CRITICAL", source="A", epss_score=0.0, epss_percent="0%", kev_match=False, risk_heat_score=0, description="desc", fix_version=None, published_date=None, last_modified_date=None, nvd_url=""),
        VulnerabilityFinding(package=pkg, cve_id="CVE-BAD", cvss_score=11.0, cvss_severity="HIGH", source="A", epss_score=0.0, epss_percent="0%", kev_match=False, risk_heat_score=0, description="desc", fix_version=None, published_date=None, last_modified_date=None, nvd_url=""), # Malformed & invalid bounds
    ]
    
    unique = VulnerabilityDataValidator.deduplicate_findings(findings)
    assert len(unique) == 2
    assert unique[0].cve_id == "CVE-2022-1111"
    assert unique[1].cve_id == "CVE-2022-2222"
