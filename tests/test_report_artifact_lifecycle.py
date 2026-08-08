import pytest
from pathlib import Path
from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.history import HistoryService
from pulse.reporting.report_service import ReportService
from pulse.reporting.context import ReportContext


class TestReportArtifactLifecycle:
    """Component 5 & Bug 20, 21, 24 – Tests exact report path persistence, retrieval, missing file handling, and lifecycle."""

    def test_export_report_lifecycle(self, tmp_path):
        history = HistoryService()
        dummy_pkg = PackageInfo(name="testpkg", version="1.0.0", ecosystem="pypi")
        finding = VulnerabilityFinding(
            package=dummy_pkg,
            cve_id="CVE-2022-1234",
            cvss_score=8.5,
            cvss_severity="HIGH",
            epss_score=0.1,
            epss_percent="10%",
            kev_match=False,
            risk_heat_score=85,
            description="Test vulnerability",
            fix_version="1.0.1",
            source="OSV",
            nvd_url="https://nvd.nist.gov"
        )
        scan = ScanResult(
            timestamp=datetime.now(),
            hostname="testhost",
            tool_version="4.0.0",
            packages_scanned=1,
            attack_surface_score=85,
            scan_duration_seconds=1.0,
            findings=[finding]
        )

        scan_id = history.save_scan(scan)
        scan.id = scan_id

        # 1. Generate report to custom output directory
        ctx = ReportContext(scan_result=scan, scan_id=str(scan_id))
        out_dir = tmp_path / "reports"
        generated = ReportService.generate_reports(ctx, formats=["html"], custom_output_dir=out_dir)

        html_path = generated["html"]
        assert html_path.exists()

        # 2. Register and confirm database/history stores exact path
        history.register_report_artifact(str(scan_id), "html", str(html_path.resolve()))
        artifact = history.get_report_artifact(str(scan_id), "html")
        assert artifact is not None
        assert str(Path(artifact["path"]).resolve()) == str(html_path.resolve())

        # 3. Test get_last_report() returns exact persisted path
        last_info = ReportService.get_last_report(history_service=history)
        assert last_info is not None
        assert str(last_info["html_path"].resolve()) == str(html_path.resolve())
        assert last_info["missing"] is False

        # 4. Manually delete exported file
        html_path.unlink()

        # 5. Confirm get_last_report reports exact missing path
        last_info_missing = ReportService.get_last_report(history_service=history)
        assert last_info_missing["missing"] is True
        assert str(last_info_missing["html_path"].resolve()) == str(html_path.resolve())

        # 6. Export again and confirm new artifact is recorded
        new_generated = ReportService.generate_reports(ctx, formats=["html"], custom_output_dir=out_dir)
        new_html_path = new_generated["html"]
        assert new_html_path.exists()

        new_artifact = history.get_latest_report_artifact("html")
        assert new_artifact is not None
        assert str(Path(new_artifact["path"]).resolve()) == str(new_html_path.resolve())
