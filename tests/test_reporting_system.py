import json
import pytest
from datetime import datetime, timedelta
from pathlib import Path
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, WebsiteAssessment, TechnologyFingerprint, CorrelationStatus
from pulse.reporting.context import ReportContext
from pulse.reporting.models import ReportModel, Severity, BaseSection, WebsiteAssessmentSection, DependencyInventorySection, RemediationSection
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.renderers import JSONRenderer, SARIFRenderer, MarkdownRenderer, HTMLRenderer
from pulse.reporting.report_service import ReportService

@pytest.fixture
def mock_scan_result():
    pkg1 = PackageInfo(name="requests", version="2.28.0", ecosystem="PyPI")
    pkg2 = PackageInfo(name="urllib3", version="1.26.5", ecosystem="PyPI")

    finding1 = VulnerabilityFinding(
        package=pkg1,
        cve_id="CVE-2023-9999",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.9,
        epss_percent="90%",
        kev_match=True,
        risk_heat_score=95,
        description="Critical Remote Code Execution",
        fix_version="2.28.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-9999"
    )

    finding2 = VulnerabilityFinding(
        package=pkg2,
        cve_id="CVE-2023-1111",
        cvss_score=6.5,
        cvss_severity="MEDIUM",
        epss_score=0.05,
        epss_percent="5%",
        kev_match=False,
        risk_heat_score=40,
        description="Medium flaw in buffer reading",
        fix_version="1.26.6",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-1111"
    )

    scan = ScanResult(
        timestamp=datetime(2026, 7, 26, 12, 0, 0),
        hostname="test-node",
        tool_version="4.0.0",
        packages_scanned=10,
        attack_surface_score=75,
        scan_duration_seconds=3.5,
        findings=[finding1, finding2],
        target_type="project",
        target_id="my_project"
    )
    return scan

def test_report_context_creation(mock_scan_result):
    now = datetime.now()
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153", generated_at=now)
    assert ctx.scan_result == mock_scan_result
    assert ctx.scan_id == "000153"
    assert ctx.generated_at == now

def test_report_builder_pure(mock_scan_result):
    now = datetime(2026, 7, 26, 12, 5, 0)
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153", generated_at=now)
    model = ReportBuilder.build(ctx)

    assert isinstance(model, ReportModel)
    assert model.executive_summary.target_id == "my_project"
    assert model.executive_summary.target_type == "project"
    assert model.executive_summary.packages_scanned == 10
    assert model.executive_summary.vulnerable_count == 2
    assert model.executive_summary.attack_surface_score == 75

    assert model.risk_summary.critical_count == 1
    assert model.risk_summary.medium_count == 1
    assert model.risk_summary.kev_matches_count == 1

    assert len(model.findings) == 2
    assert model.findings[0].severity == Severity.CRITICAL
    assert model.findings[0].remediation_command == "pip install requests==2.28.1"

    assert model.metadata.pulse_version == "4.0.0"
    assert model.metadata.report_schema_version == "2.0"
    assert model.metadata.template_version == "1.0"
    assert model.metadata.generated_at == now

def test_json_renderer_canonical(mock_scan_result):
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153")
    model = ReportBuilder.build(ctx)
    renderer = JSONRenderer()
    content = renderer.render(model)

    data = json.loads(content)
    assert data["metadata"]["report_schema_version"] == "2.0"
    assert data["metadata"]["template_version"] == "1.0"
    assert data["executive_summary"]["target_id"] == "my_project"
    assert data["risk_summary"]["critical_count"] == 1
    assert len(data["findings"]) == 2

def test_sarif_renderer_output(mock_scan_result):
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153")
    model = ReportBuilder.build(ctx)
    renderer = SARIFRenderer()
    content = renderer.render(model)

    data = json.loads(content)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == 2

def test_markdown_renderer_output(mock_scan_result):
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153")
    model = ReportBuilder.build(ctx)
    renderer = MarkdownRenderer()
    content = renderer.render(model)

    assert "# PULSE Security Scan Report" in content
    assert "CVE-2023-9999" in content
    assert "pip install requests==2.28.1" in content

def test_html_renderer_output(mock_scan_result):
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153")
    model = ReportBuilder.build(ctx)
    renderer = HTMLRenderer()
    content = renderer.render(model)

    assert "<!DOCTYPE html>" in content
    assert "PULSE Security Dashboard" in content
    assert "High Risk" in content or "Moderate Risk" in content
    assert "CVE-2023-9999" in content
    assert "filterSeverity" in content
    assert "pip install requests==2.28.1" in content

def test_report_service_folder_storage(tmp_path, mock_scan_result, monkeypatch):
    monkeypatch.setattr("pulse.reporting.report_service.ReportService.get_reports_dir", lambda: tmp_path)
    ctx = ReportContext(scan_result=mock_scan_result, scan_id="000153")
    generated = ReportService.generate_reports(ctx)

    scan_dir = tmp_path / "scan_000153"
    assert scan_dir.exists()
    assert generated["html"].exists()
    assert generated["json"].exists()
    assert generated["markdown"].exists()
    assert generated["sarif"].exists()

def test_website_scan_report(tmp_path, monkeypatch):
    monkeypatch.setattr("pulse.reporting.report_service.ReportService.get_reports_dir", lambda: tmp_path)
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="web-test",
        tool_version="4.0.0",
        packages_scanned=0,
        attack_surface_score=45,
        scan_duration_seconds=2.0,
        target_type="website",
        target_id="https://example.com",
        website_assessment=WebsiteAssessment(
            url="https://example.com",
            correlation_status=CorrelationStatus.COMPLETED,
            technologies=[
                TechnologyFingerprint(name="wordpress", version="6.1.1", category="CMS", confidence=90, correlation_supported=True)
            ]
        )
    )

    ctx = ReportContext(scan_result=scan, scan_id="000154")
    model = ReportBuilder.build(ctx)
    assert any(isinstance(s, WebsiteAssessmentSection) for s in model.sections)

    renderer = HTMLRenderer()
    html = renderer.render(model)
    assert "Website Technology Assessment" in html
    assert "wordpress" in html

def test_reporting_settings_locations(tmp_path, monkeypatch):
    from pulse.config import set_setting
    # Test PWD setting
    monkeypatch.setattr("pathlib.Path.cwd", lambda: tmp_path)
    set_setting("REPORT_DEFAULT_LOCATION", "pwd")
    reports_dir = ReportService.get_reports_dir()
    assert reports_dir == tmp_path / "pulse-reports"

    # Test Custom setting
    custom_dir = tmp_path / "custom_reports"
    set_setting("REPORT_DEFAULT_LOCATION", "custom")
    set_setting("REPORT_CUSTOM_DIR", str(custom_dir))
    reports_dir_custom = ReportService.get_reports_dir()
    assert reports_dir_custom == custom_dir

    # Reset
    set_setting("REPORT_DEFAULT_LOCATION", "pulse")

def test_cleanup_old_reports(tmp_path, monkeypatch):
    from pulse.config import set_setting
    monkeypatch.setattr("pulse.reporting.report_service.ReportService.get_reports_dir", lambda: tmp_path)
    set_setting("REPORT_KEEP_HISTORY", "3")

    for i in range(5):
        d = tmp_path / f"scan_{i:06d}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.html").write_text("test")

    ReportService._cleanup_old_reports()
    remaining = [d.name for d in tmp_path.iterdir() if d.is_dir() and d.name.startswith("scan_")]
    assert len(remaining) <= 3

