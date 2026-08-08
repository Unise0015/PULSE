import io
import json
import pytest
from datetime import datetime
from rich.console import Console

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.version_intelligence.models import UpgradeRecommendation
from pulse.ui import print_highest_risk_finding, print_remediation_table
from pulse.state import AppState
from pulse.reporter import export_json, export_markdown, export_csv, export_html, export_sarif

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

def test_default_cli_hides_rejected_candidates_and_candidate_reason(mock_rejected_django_scan):
    AppState.DEBUG_MODE = False
    scan, finding, rec = mock_rejected_django_scan

    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=140)

    print_highest_risk_finding(console, finding, scan=scan)
    rendered = output.getvalue()

    assert "6.1" in rendered
    assert "Lowest Candidate Fix" not in rendered
    assert "Rejected Candidates" not in rendered
    assert "5.1.14 was rejected" not in rendered
    assert "Verification" in rendered
    assert "Status" in rendered
    assert "✅ Verified Safe" in rendered

def test_debug_mode_shows_rejected_candidates(mock_rejected_django_scan):
    AppState.DEBUG_MODE = True
    try:
        scan, finding, rec = mock_rejected_django_scan

        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=140)

        print_highest_risk_finding(console, finding, scan=scan)
        rendered = output.getvalue()

        assert "6.1" in rendered
        assert "Lowest Candidate Fix" in rendered
        assert "Rejected Candidates" in rendered
        assert "5.1.14" in rendered
    finally:
        AppState.DEBUG_MODE = False

def test_cve_context_preserved_in_default_mode(mock_rejected_django_scan):
    """Verify that CVE/security context fields are NOT removed by UX simplification."""
    AppState.DEBUG_MODE = False
    scan, finding, rec = mock_rejected_django_scan

    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=140)
    print_highest_risk_finding(console, finding, scan=scan)
    rendered = output.getvalue()

    assert "CVE-2021-45452" in rendered
    assert "Severity" in rendered
    assert "CVSS Score" in rendered
    assert "KEV Match" in rendered
    assert "Risk Heat Score" in rendered
    assert "Attack Path" in rendered

def test_latest_stable_always_shown(mock_rejected_django_scan):
    AppState.DEBUG_MODE = False
    scan, finding, rec = mock_rejected_django_scan

    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=140)
    print_highest_risk_finding(console, finding, scan=scan)
    rendered = output.getvalue()

    assert "Latest Stable" in rendered

def test_upgrade_command_exact_pin(mock_rejected_django_scan):
    AppState.DEBUG_MODE = False
    scan, finding, rec = mock_rejected_django_scan

    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=140)
    print_highest_risk_finding(console, finding, scan=scan)
    rendered = output.getvalue()

    assert "pip install Django==6.1" in rendered
    assert ">=6.1,<7" not in rendered

def test_exports_retain_full_metadata(mock_rejected_django_scan, tmp_path):
    scan, finding, rec = mock_rejected_django_scan

    json_path = tmp_path / "report.json"
    export_json(scan, json_path)
    json_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_data["findings"][0]["fix_version"] == "6.1"

    md_path = tmp_path / "report.md"
    export_markdown(scan, md_path)
    assert "6.1" in md_path.read_text(encoding="utf-8")

    html_path = tmp_path / "report.html"
    export_html(scan, html_path)
    assert "6.1" in html_path.read_text(encoding="utf-8")
