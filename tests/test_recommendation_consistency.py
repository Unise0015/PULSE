import io
import json
import pytest
from datetime import datetime
from rich.console import Console

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.version_intelligence.models import UpgradeRecommendation
from pulse.ui import print_highest_risk_finding, print_remediation_table
from pulse.reporter import export_json, export_markdown, export_csv, export_html, export_sarif
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.context import ReportContext
from pulse.state import AppState

@pytest.fixture
def mock_rejected_django_scan():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")
    finding = VulnerabilityFinding(
        cve_id="CVE-2021-45452",
        package=pkg,
        cvss_score=8.5,
        cvss_severity="HIGH",
        fix_version="5.1.14",
        source="OSV"
    )
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

def test_cli_highest_risk_panel_consistency(mock_rejected_django_scan):
    AppState.DEBUG_MODE = False
    scan, finding, rec = mock_rejected_django_scan
    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=120)

    print_highest_risk_finding(console, finding, scan=scan)
    rendered = output.getvalue()

    assert "6.1" in rendered
    assert "Lowest Candidate Fix" not in rendered
    assert "5.1.14" not in rendered

def test_cli_dashboard_consistency(mock_rejected_django_scan):
    AppState.DEBUG_MODE = False
    scan, finding, rec = mock_rejected_django_scan
    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=120)

    print_remediation_table(console, scan)
    rendered = output.getvalue()

    assert "6.1" in rendered
    assert "Lowest Candidate Fix" not in rendered

def test_json_export_consistency(mock_rejected_django_scan, tmp_path):
    scan, finding, rec = mock_rejected_django_scan
    out_file = tmp_path / "report.json"
    export_json(scan, out_file)

    data = json.loads(out_file.read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    assert len(findings) > 0
    assert findings[0]["fix_version"] == "6.1"

def test_markdown_export_consistency(mock_rejected_django_scan, tmp_path):
    scan, finding, rec = mock_rejected_django_scan
    out_file = tmp_path / "report.md"
    export_markdown(scan, out_file)

    content = out_file.read_text(encoding="utf-8")
    assert "6.1" in content

def test_csv_export_consistency(mock_rejected_django_scan, tmp_path):
    scan, finding, rec = mock_rejected_django_scan
    out_file = tmp_path / "report.csv"
    export_csv(scan, out_file)

    content = out_file.read_text(encoding="utf-8")
    assert "6.1" in content

def test_html_export_consistency(mock_rejected_django_scan, tmp_path):
    scan, finding, rec = mock_rejected_django_scan
    out_file = tmp_path / "report.html"
    export_html(scan, out_file)

    content = out_file.read_text(encoding="utf-8")
    assert "6.1" in content

def test_sarif_export_consistency(mock_rejected_django_scan, tmp_path):
    scan, finding, rec = mock_rejected_django_scan
    out_file = tmp_path / "report.sarif"
    export_sarif(scan, out_file)

    content = out_file.read_text(encoding="utf-8")
    assert "6.1" in content
