import json
import pytest
from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.reporter import export_json, export_csv, export_markdown, export_html, export_sarif

@pytest.fixture
def sample_scan_with_attack_path():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")
    finding = VulnerabilityFinding(
        cve_id="CVE-2022-34265",
        package=pkg,
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        fix_version="6.1",
        description="SQL Injection vulnerability in Django."
    )
    finding.attack_techniques = [
        AttackTechnique(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", confidence="High"),
        AttackTechnique(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution", confidence="Medium")
    ]

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=85,
        findings=[finding]
    )
    return scan

class TestAttackPathExports:
    """Verify exports retain both technique ID and name."""

    def test_json_export_contains_technique_id_and_name(self, sample_scan_with_attack_path, tmp_path):
        json_path = tmp_path / "report.json"
        export_json(sample_scan_with_attack_path, json_path)
        data = json.loads(json_path.read_text(encoding="utf-8"))

        finding = data["findings"][0]
        assert "attack_techniques" in finding
        techs = finding["attack_techniques"]
        assert len(techs) == 2
        assert techs[0]["id"] == "T1190"
        assert techs[0]["name"] == "Exploit Public-Facing Application"
        assert techs[1]["id"] == "T1059"
        assert techs[1]["name"] == "Command and Scripting Interpreter"

    def test_csv_export_contains_technique_id_and_name(self, sample_scan_with_attack_path, tmp_path):
        csv_path = tmp_path / "report.csv"
        export_csv(sample_scan_with_attack_path, str(csv_path))
        content = csv_path.read_text(encoding="utf-8")

        assert "T1190 — Exploit Public-Facing Application" in content
        assert "T1059 — Command and Scripting Interpreter" in content

    def test_sarif_export_contains_technique_id_and_name(self, sample_scan_with_attack_path, tmp_path):
        sarif_path = tmp_path / "report.sarif"
        export_sarif(sample_scan_with_attack_path, sarif_path)
        data = json.loads(sarif_path.read_text(encoding="utf-8"))

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        props = rules[0]["properties"]
        assert "attackTechniques" in props
        techs = props["attackTechniques"]
        assert techs[0]["id"] == "T1190"
        assert techs[0]["name"] == "Exploit Public-Facing Application"
