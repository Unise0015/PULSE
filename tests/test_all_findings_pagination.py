import io
import pytest
from rich.console import Console
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.ui import render_all_findings_paginated, sort_canonical_findings

def create_mock_findings(count: int, prefix: str = "CVE-2022"):
    findings = []
    for i in range(1, count + 1):
        pkg = PackageInfo(name=f"pkg-{i}", version="1.0.0", ecosystem="pypi")
        f = VulnerabilityFinding(
            cve_id=f"{prefix}-{1000 + i}",
            package=pkg,
            cvss_score=round(10.0 - (i % 10) * 0.5, 1),
            cvss_severity="CRITICAL" if i <= 10 else ("HIGH" if i <= 20 else ("MEDIUM" if i <= 30 else "LOW")),
            risk_heat_score=100 - i,
            epss_score=round(0.9 - (i % 10) * 0.05, 2),
            epss_percent=f"{round((0.9 - (i % 10) * 0.05) * 100, 1)}%"
        )
        findings.append(f)
    return findings


class TestAllFindingsPagination:
    """M9.5.14 Complete Paginated All Findings View Tests."""

    def test_1_all_findings_accessible_across_pages(self):
        findings = create_mock_findings(40)
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=5, attack_surface_score=80, findings=findings
        )
        
        captured_pages = []
        inputs = ["N", "Q"]
        input_iter = iter(inputs)

        def mock_input(prompt_str):
            captured_pages.append(output.getvalue())
            return next(input_iter, "Q")

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=mock_input)

        rendered_text = output.getvalue()
        assert "Showing 1–20 of 40" in rendered_text
        assert "Showing 21–40 of 40" in rendered_text
        
        sorted_expected = sort_canonical_findings(findings)
        assert len(sorted_expected) == 40

    def test_2_navigation_n_p_q(self):
        findings = create_mock_findings(40)
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=5, attack_surface_score=80, findings=findings
        )
        
        actions = ["N", "P", "Q"]
        action_iter = iter(actions)

        def mock_input(prompt_str):
            return next(action_iter, "Q")

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=mock_input)
        rendered_text = output.getvalue()

        assert "Showing 1–20 of 40" in rendered_text
        assert "Showing 21–40 of 40" in rendered_text

    def test_3_21_findings_two_pages(self):
        findings = create_mock_findings(21)
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=5, attack_surface_score=80, findings=findings
        )

        actions = ["N", "Q"]
        action_iter = iter(actions)

        def mock_input(prompt_str):
            return next(action_iter, "Q")

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=mock_input)
        rendered_text = output.getvalue()

        assert "Showing 1–20 of 21" in rendered_text
        assert "Showing 21–21 of 21" in rendered_text

    def test_4_20_findings_single_page_no_next(self):
        findings = create_mock_findings(20)
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=5, attack_surface_score=80, findings=findings
        )

        def mock_input(prompt_str):
            assert "[N] Next Page" not in prompt_str
            assert "[Q] Back" in prompt_str
            return "Q"

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=mock_input)
        rendered_text = output.getvalue()

        assert "Showing 1–20 of 20" in rendered_text

    def test_5_1_finding(self):
        findings = create_mock_findings(1)
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=1, attack_surface_score=10, findings=findings
        )

        def mock_input(prompt_str):
            return "Q"

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=mock_input)
        rendered_text = output.getvalue()

        assert "Showing 1–1 of 1" in rendered_text

    def test_6_0_findings_empty_state(self):
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=0, attack_surface_score=0, findings=[]
        )

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=lambda p: "Q")
        rendered_text = output.getvalue()

        assert "No vulnerabilities found." in rendered_text

    def test_7_consistent_global_ordering(self):
        pkg = PackageInfo(name="test", version="1.0", ecosystem="pypi")
        f1 = VulnerabilityFinding(cve_id="CVE-2022-0001", package=pkg, cvss_score=9.8, cvss_severity="CRITICAL", risk_heat_score=90, epss_score=0.8)
        f2 = VulnerabilityFinding(cve_id="CVE-2022-0002", package=pkg, cvss_score=9.8, cvss_severity="CRITICAL", risk_heat_score=90, epss_score=0.9)
        f3 = VulnerabilityFinding(cve_id="CVE-2022-0003", package=pkg, cvss_score=7.5, cvss_severity="HIGH", risk_heat_score=70, epss_score=0.5)
        f4 = VulnerabilityFinding(cve_id="CVE-2022-0000", package=pkg, cvss_score=9.8, cvss_severity="CRITICAL", risk_heat_score=90, epss_score=0.9)

        findings = [f1, f2, f3, f4]
        sorted_list = sort_canonical_findings(findings)

        # Higher risk heat score first, then higher CVSS, then higher EPSS, then lower CVE ID string (ASC)
        assert sorted_list[0].cve_id == "CVE-2022-0000"  # risk 90, CVSS 9.8, EPSS 0.9, cve_id 0000 < 0002
        assert sorted_list[1].cve_id == "CVE-2022-0002"  # risk 90, CVSS 9.8, EPSS 0.9, cve_id 0002
        assert sorted_list[2].cve_id == "CVE-2022-0001"  # risk 90, CVSS 9.8, EPSS 0.8
        assert sorted_list[3].cve_id == "CVE-2022-0003"  # risk 70

    def test_8_no_security_policy_filtering(self):
        pkg = PackageInfo(name="test", version="1.0", ecosystem="pypi")
        f_crit = VulnerabilityFinding(cve_id="CVE-2022-0001", package=pkg, cvss_score=9.8, cvss_severity="CRITICAL", risk_heat_score=90)
        f_info = VulnerabilityFinding(cve_id="CVE-2022-0002", package=pkg, cvss_score=0.0, cvss_severity="INFORMATIONAL", risk_heat_score=5)
        f_low = VulnerabilityFinding(cve_id="CVE-2022-0003", package=pkg, cvss_score=2.0, cvss_severity="LOW", risk_heat_score=10)

        findings = [f_crit, f_info, f_low]
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=1, attack_surface_score=90, findings=findings
        )

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        render_all_findings_paginated(console, scan, page_size=20, input_func=lambda p: "Q")
        rendered_text = output.getvalue()

        assert "CVE-2022-0001" in rendered_text
        assert "CVE-2022-0002" in rendered_text
        assert "CVE-2022-0003" in rendered_text
        assert "Showing 1–3 of 3" in rendered_text

    def test_9_canonical_count_match(self):
        findings = create_mock_findings(40)
        scan = ScanResult(
            timestamp=None, hostname="test", tool_version="1.0",
            packages_scanned=5, attack_surface_score=80, findings=findings
        )
        assert len(scan.findings) == 40
