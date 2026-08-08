import io
import pytest
from datetime import datetime
from rich.console import Console

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.version_intelligence.models import UpgradeRecommendation
from pulse.ui import print_highest_risk_finding

@pytest.fixture
def sample_finding_with_attack_path():
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

    rec = UpgradeRecommendation(
        package_name="Django",
        ecosystem="pypi",
        current_version="3.2",
        latest_stable="6.1",
        recommended_version="6.1",
        verified_safe=True
    )
    scan.upgrade_recommendations[scan.make_package_key("pypi", "Django")] = rec
    return scan, finding

class TestAttackPathRendering:
    """Verify Highest Risk Finding renders ATT&CK IDs with human-readable names."""

    def test_attack_path_renders_ids_and_names(self, sample_finding_with_attack_path):
        scan, finding = sample_finding_with_attack_path

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)
        print_highest_risk_finding(console, finding, scan=scan)
        rendered = output.getvalue()

        assert "CVE-2022-34265" in rendered
        assert "T1190 — Exploit Public-Facing Application" in rendered
        assert "T1059 — Command and Scripting Interpreter" in rendered
