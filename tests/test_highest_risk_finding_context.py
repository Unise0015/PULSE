import io
import pytest
from datetime import datetime
from rich.console import Console

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.version_intelligence.models import UpgradeRecommendation
from pulse.ui import print_highest_risk_finding
from pulse.state import AppState

@pytest.fixture
def mock_django_scan():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")
    finding = VulnerabilityFinding(
        cve_id="CVE-2022-34265",
        package=pkg,
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        fix_version="5.1.14",
        source="OSV",
        cwe="CWE-89",
        epss_percent="73.3%",
        risk_heat_score=71,
        description="TruncateHTML and Extract functions in Django 3.2 before 3.2.14 are subject to SQL Injection."
    )
    finding._cwe_name = "SQL Injection"
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
        minimum_known_safe="5.1.14",
        latest_stable="6.1",
        recommended_version="6.1",
        rejected_candidates=["5.1.14"],
        verified_safe=True,
        recommendation_reason="5.1.14 was rejected because verification detected blocking vulnerabilities."
    )

    key = scan.make_package_key("pypi", "Django")
    scan.upgrade_recommendations[key] = rec
    return scan, finding, rec


class TestHighestRiskFindingContext:
    """Verify the Highest Risk Finding panel preserves complete CVE & ATT&CK context."""

    def test_cve_and_attack_path_always_shown(self, mock_django_scan):
        AppState.DEBUG_MODE = False
        scan, finding, rec = mock_django_scan

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)
        print_highest_risk_finding(console, finding, scan=scan)
        rendered = output.getvalue()

        assert "CVE-2022-34265" in rendered
        assert "CWE-89" in rendered
        assert "SQL Injection" in rendered
        assert "CRITICAL" in rendered
        assert "9.8" in rendered
        assert "73.3%" in rendered
        assert "71" in rendered
        assert "Vulnerability Summary" in rendered
        assert "SQL Injection" in rendered
        assert "Attack Path" in rendered
        assert "T1190 — Exploit Public-Facing Application" in rendered
        assert "T1059 — Command and Scripting Interpreter" in rendered

    def test_upgrade_analysis_shown(self, mock_django_scan):
        AppState.DEBUG_MODE = False
        scan, finding, rec = mock_django_scan

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)
        print_highest_risk_finding(console, finding, scan=scan)
        rendered = output.getvalue()

        assert "Current Version" in rendered
        assert "3.2" in rendered
        assert "Latest Stable" in rendered
        assert "6.1" in rendered
        assert "Recommended Version" in rendered
        assert "Verified Safe" in rendered
        assert "Migration Risk" in rendered
        assert "Verification" in rendered

    def test_upgrade_command_exact_pin(self, mock_django_scan):
        AppState.DEBUG_MODE = False
        scan, finding, rec = mock_django_scan

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)
        print_highest_risk_finding(console, finding, scan=scan)
        rendered = output.getvalue()

        assert "pip install Django==6.1" in rendered
        assert ">=6.1,<7" not in rendered
