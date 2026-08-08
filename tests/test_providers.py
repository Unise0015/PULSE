import pytest
from pulse.domain.models import PackageInfo
from pulse.vulnerability.osv_provider import OSVProvider
from pulse.vulnerability.threat_intel import EPSSProvider, KEVProvider

def test_osv_parser():
    provider = OSVProvider()
    pkg = PackageInfo("requests", "2.27.0", "python", "DIRECT", "UNKNOWN")
    
    # Mock response
    mock_response = {
        "vulns": [
            {
                "id": "GHSA-xxxx",
                "aliases": ["CVE-2023-32681"],
                "summary": "Test vuln",
                "published": "2023-01-01",
                "modified": "2023-01-02"
            }
        ]
    }
    
    findings = provider._parse_osv_response(pkg, mock_response)
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2023-32681"
    assert findings[0].description == "Test vuln"
    
def test_osv_parser_fallback():
    provider = OSVProvider()
    pkg = PackageInfo("requests", "2.27.0", "python", "DIRECT", "UNKNOWN")
    
    mock_response = {
        "vulns": [
            {
                "id": "GHSA-yyyy",
                # No aliases
                "details": "Test details"
            }
        ]
    }
    
    findings = provider._parse_osv_response(pkg, mock_response)
    assert len(findings) == 1
    assert findings[0].cve_id == "GHSA-yyyy"

# We mock actual HTTP logic for KEV since it downloads a large JSON
def test_kev_provider_match(monkeypatch):
    provider = KEVProvider()
    
    # Mock the get_catalog method
    def mock_catalog():
        return {
            "CVE-2023-1234": {"dateAdded": "2023-05-01"}
        }
    monkeypatch.setattr(provider, "get_catalog", mock_catalog)
    
    from pulse.domain.models import VulnerabilityFinding
    pkg = PackageInfo("test", "1.0", "python", "DIRECT", "UNKNOWN")
    f1 = VulnerabilityFinding(pkg, "CVE-2023-1234", 0, "", 0, "", False, 0, "", None, "", "", "", "")
    f2 = VulnerabilityFinding(pkg, "CVE-2023-9999", 0, "", 0, "", False, 0, "", None, "", "", "", "")
    
    findings = [f1, f2]
    provider.enrich_findings(findings)
    
    assert f1.kev_match is True
    assert f1.kev_date_added == "2023-05-01"
    assert f2.kev_match is False
