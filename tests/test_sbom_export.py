import json
from pathlib import Path
from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.supply_chain.sbom import export_cyclonedx

def test_export_cyclonedx_valid_structure(tmp_path):
    pkg = PackageInfo(name="django", version="3.2.0", ecosystem="python")
    
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-1234",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.15,
        epss_percent="15%",
        kev_match=True,
        risk_heat_score=98,
        description="A SQL injection vulnerability exists in Django.",
        fix_version="4.2.0",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
        cwe="CWE-89",
        attack_techniques=[
            AttackTechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "High"),
            AttackTechnique("T1059", "Command and Scripting Interpreter", "Execution", "High")
        ]
    )
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0.0",
        packages_scanned=10,
        attack_surface_score=50,
        scan_duration_seconds=1.0,
        findings=[finding]
    )
    
    out_file = tmp_path / "sbom.json"
    export_cyclonedx(scan, str(out_file))
    
    assert out_file.exists()
    
    with open(out_file, "r") as f:
        bom = json.load(f)
        
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.4"
    assert len(bom["components"]) == 1
    
    comp = bom["components"][0]
    assert comp["name"] == "django"
    assert comp["purl"] == "pkg:pypi/django@3.2.0"
    
    # Check threat properties
    props = comp.get("properties", [])
    prop_names = {p["name"]: p["value"] for p in props}
    assert "pulse.attack_techniques" in prop_names
    assert "T1190" in prop_names["pulse.attack_techniques"]
    assert "pulse.attack_tactics" in prop_names
    assert "pulse.kev_match" in prop_names
    assert prop_names["pulse.kev_match"] == "true"
    
    # Check vulnerabilities
    assert len(bom["vulnerabilities"]) == 1
    vuln = bom["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2023-1234"
    assert vuln["source"]["name"] == "OSV"
    assert vuln["ratings"][0]["score"] == 9.8
    assert vuln["ratings"][0]["severity"] == "critical"
    assert vuln["cwes"] == [89]
    assert vuln["affects"][0]["ref"] == comp["bom-ref"]
    
    # Check epss property
    vuln_props = {p["name"]: p["value"] for p in vuln.get("properties", [])}
    assert "pulse.epss_score" in vuln_props
    assert vuln_props["pulse.epss_score"] == "0.15"
