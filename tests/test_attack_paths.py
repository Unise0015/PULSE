from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.supply_chain.attack_paths import AttackPathAnalyzer
from pulse.reporter import export_attack_paths_json
import json

def test_attack_path_exclusive_scoring():
    pkg = PackageInfo(name="django", version="3.2.0", ecosystem="python")
    
    # Base finding
    f1 = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-1001",
        cvss_score=9.5,
        cvss_severity="CRITICAL",
        epss_score=0.10,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=95,
        description="Test 1",
        fix_version="3.2.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov"
    )
    
    # KEV (+40), EPSS > 0.5 (+25), CVSS >= 9 (+20), MITRE (+10) -> 95
    f2 = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-1002",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.60,
        epss_percent="60%",
        kev_match=True,
        risk_heat_score=98,
        description="Test 2",
        fix_version="3.2.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov",
        attack_techniques=[AttackTechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "High")]
    )
    
    # CVSS >= 7 but < 9 (+10) -> 10
    f3 = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-1003",
        cvss_score=7.5,
        cvss_severity="HIGH",
        epss_score=0.10,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=75,
        description="Test 3",
        fix_version="3.2.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov"
    )
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=100,
        scan_duration_seconds=1.0,
        findings=[f1, f2, f3]
    )
    
    AttackPathAnalyzer.generate(scan)
    
    assert len(scan.attack_paths) == 3
    # Sorted by exposure score
    assert scan.attack_paths[0].cve_id == "CVE-2023-1002"
    assert scan.attack_paths[0].exposure_score == 95
    
    assert scan.attack_paths[1].cve_id == "CVE-2023-1001"
    assert scan.attack_paths[1].exposure_score == 20
    
    assert scan.attack_paths[2].cve_id == "CVE-2023-1003"
    assert scan.attack_paths[2].exposure_score == 10
    
    # Check tactics extraction
    assert scan.attack_paths[0].attack_tactics == ["Initial Access"]

def test_attack_path_export_json(tmp_path):
    pkg = PackageInfo(name="django", version="3.2.0", ecosystem="python")
    f1 = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-1002",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.60,
        epss_percent="60%",
        kev_match=True,
        risk_heat_score=98,
        description="Test 2",
        fix_version="3.2.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov",
        attack_techniques=[AttackTechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "High")]
    )
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=100,
        scan_duration_seconds=1.0,
        findings=[f1]
    )
    
    AttackPathAnalyzer.generate(scan)
    
    out_file = tmp_path / "attack_paths.json"
    export_attack_paths_json(scan, out_file)
    
    assert out_file.exists()
    
    with open(out_file, "r") as f:
        data = json.load(f)
        
    assert "attack_paths" in data
    paths = data["attack_paths"]
    assert len(paths) == 1
    assert paths[0]["exposure_score"] == 95
    assert paths[0]["cve_id"] == "CVE-2023-1002"
    assert "Initial Access" in paths[0]["attack_tactics"]
