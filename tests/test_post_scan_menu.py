import pytest
import ast
from pathlib import Path


class TestPostScanMenuStructure:
    """Verify the post-scan menu structure matches the simplified specification."""

    def _get_post_scan_menu_source(self):
        """Extract the post_scan_menu function source from cli.py."""
        cli_path = Path(__file__).resolve().parent.parent / "src" / "pulse" / "cli.py"
        source = cli_path.read_text(encoding="utf-8")
        return source

    def test_no_highest_risk_findings_menu_entry(self):
        """View Highest Risk Findings should not appear in the menu choices."""
        source = self._get_post_scan_menu_source()
        
        # Find post_scan_menu function
        lines = source.splitlines()
        in_function = False
        for i, line in enumerate(lines, 1):
            if "def post_scan_menu" in line:
                in_function = True
                continue
            if in_function and line.startswith("def ") and "post_scan_menu" not in line:
                break
            if in_function and "View Highest Risk Findings" in line:
                pytest.fail(
                    f"post_scan_menu still contains 'View Highest Risk Findings' at line {i}"
                )

    def test_no_diagnostics_section(self):
        """Diagnostics & Observability section should not exist in the menu."""
        source = self._get_post_scan_menu_source()
        
        lines = source.splitlines()
        in_function = False
        diagnostics_items = [
            "Diagnostics & Observability",
            "View Provider Statistics",
            "View Scan Integrity",
            "View Validation Summary",
            "View Performance Metrics"
        ]
        for i, line in enumerate(lines, 1):
            if "def post_scan_menu" in line:
                in_function = True
                continue
            if in_function and line.startswith("def ") and "post_scan_menu" not in line:
                break
            if in_function:
                for item in diagnostics_items:
                    if item in line:
                        pytest.fail(
                            f"post_scan_menu still contains '{item}' at line {i}"
                        )

    def test_essential_menu_items_present(self):
        """Core menu items should still be available."""
        source = self._get_post_scan_menu_source()
        
        required_items = [
            "View Critical Vulnerabilities",
            "View All Findings",
            "View Package Upgrade Recommendations",
            "View Attack Paths",
            "View Exploit Intelligence",
            "View Dependency Tree",
            "Export Report",
            "Return to Main Menu",
        ]
        
        lines = source.splitlines()
        in_function = False
        function_body = []
        for i, line in enumerate(lines, 1):
            if "def post_scan_menu" in line:
                in_function = True
                continue
            if in_function and line.startswith("def ") and "post_scan_menu" not in line:
                break
            if in_function:
                function_body.append(line)
        
        body_text = "\n".join(function_body)
        for item in required_items:
            assert item in body_text, f"Required menu item '{item}' missing from post_scan_menu"
