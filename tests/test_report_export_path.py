import os
import pytest
from pathlib import Path
from datetime import datetime

from pulse.reporting.path_resolver import ReportPathResolver
from pulse.config import set_setting, remove_setting
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.reporter import export_json, export_html, export_markdown, export_csv, export_sarif

@pytest.fixture(autouse=True)
def reset_reporting_settings():
    remove_setting("REPORT_DEFAULT_LOCATION")
    remove_setting("REPORT_CUSTOM_DIR")
    yield
    remove_setting("REPORT_DEFAULT_LOCATION")
    remove_setting("REPORT_CUSTOM_DIR")

@pytest.fixture
def mock_scan_result():
    pkg = PackageInfo(name="django", version="3.2", ecosystem="pypi")
    f = VulnerabilityFinding(cve_id="CVE-2022-34265", package=pkg, cvss_score=9.8, cvss_severity="CRITICAL")
    return ScanResult(timestamp=datetime.now(), hostname="test", tool_version="1.0", packages_scanned=1, attack_surface_score=80, findings=[f])


class TestReportExportPath:
    """M9.5.16 Report Export Path Configuration & Resolver Tests."""

    def test_1_default_location(self):
        resolved = ReportPathResolver.resolve("report.html")
        expected_dir = Path.home() / "Documents" / "PULSE Reports"
        assert resolved.parent == expected_dir
        assert "report_" in resolved.name
        assert resolved.name.endswith(".html")

    def test_2_custom_directory(self, tmp_path):
        custom_dir = tmp_path / "SecurityReports"
        set_setting("REPORT_DEFAULT_LOCATION", "custom")
        set_setting("REPORT_CUSTOM_DIR", str(custom_dir))

        resolved = ReportPathResolver.resolve("report.html")
        assert resolved.parent == custom_dir
        assert custom_dir.exists()

    def test_3_explicit_path_overrides(self, tmp_path):
        explicit_file = tmp_path / "Exports" / "scan.html"
        set_setting("REPORT_DEFAULT_LOCATION", "custom")
        set_setting("REPORT_CUSTOM_DIR", str(tmp_path / "Ignored"))

        resolved = ReportPathResolver.resolve("report.html", explicit_path=explicit_file)
        assert resolved == explicit_file
        assert explicit_file.parent.exists()

    def test_4_no_artifacts_fallback(self):
        resolved = ReportPathResolver.resolve("report.html")
        assert "artifacts" not in str(resolved).lower().split(os.sep)
        assert str(resolved.parent).endswith("PULSE Reports")

    def test_5_directory_creation(self, tmp_path):
        target_dir = tmp_path / "Nested" / "Deep" / "Reports"
        assert not target_dir.exists()
        resolved = ReportPathResolver.resolve("report.html", configured_directory=target_dir)
        assert target_dir.exists()
        assert resolved.parent == target_dir

    def test_6_all_formats_same_directory(self, mock_scan_result, tmp_path):
        custom_dir = tmp_path / "AllFormats"
        set_setting("REPORT_DEFAULT_LOCATION", "custom")
        set_setting("REPORT_CUSTOM_DIR", str(custom_dir))

        html_p = ReportPathResolver.resolve("report", extension="html")
        json_p = ReportPathResolver.resolve("report", extension="json")
        md_p = ReportPathResolver.resolve("report", extension="md")
        csv_p = ReportPathResolver.resolve("report", extension="csv")
        sarif_p = ReportPathResolver.resolve("report", extension="sarif.json")

        assert html_p.parent == custom_dir
        assert json_p.parent == custom_dir
        assert md_p.parent == custom_dir
        assert csv_p.parent == custom_dir
        assert sarif_p.parent == custom_dir

        export_html(mock_scan_result, html_p)
        export_json(mock_scan_result, json_p)
        export_markdown(mock_scan_result, md_p)
        export_csv(mock_scan_result, str(csv_p))
        export_sarif(mock_scan_result, sarif_p)

        assert html_p.exists()
        assert json_p.exists()
        assert md_p.exists()
        assert csv_p.exists()
        assert sarif_p.exists()

    def test_7_settings_consistency(self, tmp_path):
        custom_dir = tmp_path / "ConsistentReports"
        set_setting("REPORT_DEFAULT_LOCATION", "custom")
        set_setting("REPORT_CUSTOM_DIR", str(custom_dir))

        configured_dir = ReportPathResolver.get_configured_directory()
        resolved_file = ReportPathResolver.resolve("report.html")

        assert configured_dir == custom_dir
        assert resolved_file.parent == custom_dir

    def test_8_windows_path_handling(self, tmp_path):
        win_style = str(tmp_path / "WinReports").replace("/", "\\")
        set_setting("REPORT_DEFAULT_LOCATION", "custom")
        set_setting("REPORT_CUSTOM_DIR", win_style)

        resolved = ReportPathResolver.resolve("report.html")
        assert resolved.parent == Path(win_style)
        assert Path(win_style).exists()
