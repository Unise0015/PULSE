import pytest
from pulse.domain.models import VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.vulnerability.threat_mapping import ThreatMapper

@pytest.fixture
def finding_cwe_89():
    return VulnerabilityFinding(
        package=PackageInfo(name="testpkg", version="1.0", ecosystem="python"),
        cve_id="CVE-2023-1234",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.1,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=98,
        description="SQL injection vulnerability",
        fix_version="1.1",
        source="NVD",
        published_date="2023-01-01",
        last_modified_date="2023-01-01",
        nvd_url="https://nvd.nist.gov",
        cwe="CWE-89"
    )

@pytest.fixture
def finding_no_cwe():
    return VulnerabilityFinding(
        package=PackageInfo(name="testpkg", version="1.0", ecosystem="python"),
        cve_id="CVE-2023-1234",
        cvss_score=5.0,
        cvss_severity="MEDIUM",
        epss_score=0.1,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=50,
        description="Unknown vulnerability",
        fix_version="1.1",
        source="NVD",
        published_date="2023-01-01",
        last_modified_date="2023-01-01",
        nvd_url="https://nvd.nist.gov",
        cwe=None
    )

def test_attack_mapping_single_cwe(finding_cwe_89):
    mapper = ThreatMapper()
    mapper.enrich_findings([finding_cwe_89])
    
    assert len(finding_cwe_89.attack_techniques) > 0
    tids = [t.technique_id for t in finding_cwe_89.attack_techniques]
    assert "T1190" in tids
    assert "T1059" in tids

def test_attack_mapping_no_cwe(finding_no_cwe):
    mapper = ThreatMapper()
    mapper.enrich_findings([finding_no_cwe])
    
    assert len(finding_no_cwe.attack_techniques) == 0

def test_attack_mapping_unknown_cwe(finding_cwe_89):
    finding_cwe_89.cwe = "CWE-999999"
    mapper = ThreatMapper()
    mapper.enrich_findings([finding_cwe_89])
    
    assert len(finding_cwe_89.attack_techniques) == 0

def test_attack_mapping_without_cwe_prefix(finding_cwe_89):
    finding_cwe_89.cwe = "89"
    mapper = ThreatMapper()
    mapper.enrich_findings([finding_cwe_89])
    
    assert len(finding_cwe_89.attack_techniques) > 0
    assert "T1190" in [t.technique_id for t in finding_cwe_89.attack_techniques]

def test_serialization():
    # Make sure we can construct AttackTechnique and it's basically a dataclass
    tech = AttackTechnique(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        confidence="High"
    )
    assert tech.technique_id == "T1190"
    assert tech.tactic == "Initial Access"
