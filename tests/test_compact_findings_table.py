import io
import pytest
from rich.console import Console
from pulse.domain.models import VulnerabilityFinding, PackageInfo, AttackTechnique
from pulse.ui import print_findings_table

@pytest.fixture
def sample_findings():
    findings = []
    for i in range(1, 26):
        pkg = PackageInfo(name="django", version="3.2", ecosystem="pypi")
        f = VulnerabilityFinding(
            cve_id=f"CVE-2022-342{i:02d}",
            package=pkg,
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            cwe=f"CWE-{89 if i % 2 == 0 else 20}",
            risk_heat_score=70 + i,
            epss_percent="73.3%"
        )
        f.attack_techniques = [
            AttackTechnique(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", confidence="High")
        ]
        findings.append(f)
    return findings

class TestCompactFindingsTable:
    """Verify M9.5.13 compact findings table format and pagination."""

    def test_compact_table_columns_and_formatting(self, sample_findings):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)
        
        print_findings_table(console, sample_findings[:3], page_size=20)
        rendered = output.getvalue()

        # Check compact headers
        assert "Package" in rendered
        assert "CVE" in rendered
        assert "Severity" in rendered
        assert "CVSS" in rendered
        assert "EPSS" in rendered
        assert "Risk" in rendered
        assert "KEV" in rendered
        assert "CWE" in rendered
        assert "ATT&CK" in rendered

        # Check removed detailed headers
        assert "Latest Version" not in rendered
        assert "Summary" not in rendered

        # Check compact values (ID only, no full names)
        assert "django 3.2" in rendered
        assert "CVE-2022-34201" in rendered
        assert "CWE-20" in rendered
        assert "T1190" in rendered
        assert "Exploit Public-Facing Application" not in rendered

    def test_table_pagination(self, sample_findings):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)
        
        print_findings_table(console, sample_findings, page_size=10, page=1)
        rendered = output.getvalue()

        assert "Showing 1–10 of 25" in rendered
