import pytest
from datetime import datetime
from io import StringIO
from rich.console import Console
from pulse.domain.models import (
    ScanResult, VulnerabilityFinding, PackageInfo, PostureDelta, WebsiteAssessment
)
from pulse.history import HistoryService
from pulse.ui import print_trend_summary

@pytest.fixture
def sample_package():
    return PackageInfo(name="requests", version="2.28.0", ecosystem="PyPI")

@pytest.fixture
def finding_critical(sample_package):
    return VulnerabilityFinding(
        package=sample_package,
        cve_id="CVE-2023-9999",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.9,
        epss_percent="95%",
        kev_match=True,
        risk_heat_score=95,
        description="Critical flaw",
        fix_version="2.28.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-9999"
    )

@pytest.fixture
def finding_medium(sample_package):
    return VulnerabilityFinding(
        package=sample_package,
        cve_id="CVE-2023-1111",
        cvss_score=5.3,
        cvss_severity="MEDIUM",
        epss_score=0.05,
        epss_percent="5%",
        kev_match=False,
        risk_heat_score=40,
        description="Medium flaw",
        fix_version="2.28.1",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-1111"
    )

def test_first_scan_returns_no_delta(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("pulse.history.db.get_db_path", lambda: db_file)
    from pulse.history.db import init_db
    init_db()

    service = HistoryService()

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=50,
        scan_duration_seconds=1.2,
        target_type="project",
        target_id=str(tmp_path)
    )

    delta = service.get_posture_delta(scan)
    assert delta is None

def test_second_identical_scan_delta(tmp_path, monkeypatch, finding_medium):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("pulse.history.db.get_db_path", lambda: db_file)
    from pulse.history.db import init_db
    init_db()

    service = HistoryService()

    scan1 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=40,
        scan_duration_seconds=1.2,
        findings=[finding_medium],
        target_type="project",
        target_id=str(tmp_path)
    )
    service.save_scan(scan1)

    scan2 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=40,
        scan_duration_seconds=1.0,
        findings=[finding_medium],
        target_type="project",
        target_id=str(tmp_path)
    )

    delta = service.get_posture_delta(scan2)
    assert delta is not None
    assert delta.previous_score == 40
    assert delta.current_score == 40
    assert delta.risk_score_change == 0
    assert len(delta.new_cves) == 0
    assert len(delta.remediated_cves) == 0
    assert delta.kev_change_count == 0

def test_increased_vulnerabilities_delta(tmp_path, monkeypatch, finding_medium, finding_critical):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("pulse.history.db.get_db_path", lambda: db_file)
    from pulse.history.db import init_db
    init_db()

    service = HistoryService()

    scan1 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=40,
        scan_duration_seconds=1.2,
        findings=[finding_medium],
        target_type="project",
        target_id=str(tmp_path)
    )
    service.save_scan(scan1)

    scan2 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=80,
        scan_duration_seconds=1.0,
        findings=[finding_medium, finding_critical],
        target_type="project",
        target_id=str(tmp_path)
    )

    delta = service.get_posture_delta(scan2)
    assert delta is not None
    assert delta.previous_score == 40
    assert delta.current_score == 80
    assert delta.risk_score_change == 40
    assert len(delta.new_cves) == 1
    assert delta.new_cves[0].cve_id == "CVE-2023-9999"
    assert delta.highest_new_risk.cve_id == "CVE-2023-9999"
    assert delta.kev_change_count == 1

def test_reduced_vulnerabilities_delta(tmp_path, monkeypatch, finding_medium, finding_critical):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("pulse.history.db.get_db_path", lambda: db_file)
    from pulse.history.db import init_db
    init_db()

    service = HistoryService()

    scan1 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=80,
        scan_duration_seconds=1.2,
        findings=[finding_medium, finding_critical],
        target_type="project",
        target_id=str(tmp_path)
    )
    service.save_scan(scan1)

    scan2 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=5,
        attack_surface_score=40,
        scan_duration_seconds=1.0,
        findings=[finding_medium],
        target_type="project",
        target_id=str(tmp_path)
    )

    delta = service.get_posture_delta(scan2)
    assert delta is not None
    assert delta.previous_score == 80
    assert delta.current_score == 40
    assert delta.risk_score_change == -40
    assert len(delta.remediated_cves) == 1
    assert delta.remediated_cves[0] == "CVE-2023-9999"
    assert delta.highest_resolved_cve == "CVE-2023-9999"

def test_website_scan_delta(tmp_path, monkeypatch, finding_medium):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("pulse.history.db.get_db_path", lambda: db_file)
    from pulse.history.db import init_db
    init_db()

    service = HistoryService()

    target_url = "https://example.com"
    scan1 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=0,
        attack_surface_score=30,
        scan_duration_seconds=1.2,
        findings=[],
        target_type="website",
        target_id=target_url,
        website_assessment=WebsiteAssessment(url=target_url)
    )
    service.save_scan(scan1)

    scan2 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=0,
        attack_surface_score=50,
        scan_duration_seconds=1.0,
        findings=[finding_medium],
        target_type="website",
        target_id=target_url,
        website_assessment=WebsiteAssessment(url=target_url)
    )

    delta = service.get_posture_delta(scan2)
    assert delta is not None
    assert delta.previous_score == 30
    assert delta.current_score == 50
    assert delta.risk_score_change == 20
    assert len(delta.new_cves) == 1

def test_package_scan_delta(tmp_path, monkeypatch, finding_medium):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("pulse.history.db.get_db_path", lambda: db_file)
    from pulse.history.db import init_db
    init_db()

    service = HistoryService()

    target_pkg = "pypi:requests"
    scan1 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=1,
        attack_surface_score=40,
        scan_duration_seconds=0.5,
        findings=[finding_medium],
        target_type="package",
        target_id=target_pkg
    )
    service.save_scan(scan1)

    scan2 = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=1,
        attack_surface_score=40,
        scan_duration_seconds=0.5,
        findings=[finding_medium],
        target_type="package",
        target_id=target_pkg
    )

    delta = service.get_posture_delta(scan2)
    assert delta is not None
    assert delta.previous_score == 40
    assert delta.current_score == 40

def test_print_trend_summary_rendering(finding_critical, finding_medium):
    out = StringIO()
    console = Console(file=out, width=100)

    # 1. First scan / None delta
    print_trend_summary(console, None)
    output1 = out.getvalue()
    assert "First scan for this target" in output1

    # 2. Valid delta with new critical findings
    out = StringIO()
    console = Console(file=out, width=100)
    delta_degraded = PostureDelta(
        previous_score=40,
        current_score=80,
        new_cves=[finding_critical],
        remediated_cves=[],
        risk_score_change=40,
        kev_change_count=1,
        critical_count_change=1,
        highest_new_risk=finding_critical
    )
    print_trend_summary(console, delta_degraded)
    output2 = out.getvalue()
    assert "Previous Score:" in output2
    assert "Change:" in output2
    assert "New Critical Findings:" in output2
    assert "Trend:" in output2
    assert "Degraded" in output2

    # 3. Valid delta with remediated findings
    out = StringIO()
    console = Console(file=out, width=100)
    delta_improved = PostureDelta(
        previous_score=80,
        current_score=40,
        new_cves=[],
        remediated_cves=["CVE-2023-9999"],
        risk_score_change=-40,
        kev_change_count=-1,
        critical_count_change=-1,
        highest_resolved_cve="CVE-2023-9999",
        highest_resolved_risk_score=95
    )
    print_trend_summary(console, delta_improved)
    output3 = out.getvalue()
    assert "Remediated Vulnerabilities:" in output3
    assert "Improved" in output3

    # 4. Minimal / empty PostureDelta
    out = StringIO()
    console = Console(file=out, width=100)
    delta_minimal = PostureDelta(previous_score=0, current_score=0)
    print_trend_summary(console, delta_minimal)
    output4 = out.getvalue()
    assert "Previous Score:" in output4
    assert "Stable" in output4

    # 5. Arbitrary mock object lacking expected attributes (defensive check)
    out = StringIO()
    console = Console(file=out, width=100)
    class DummyDelta:
        pass
    print_trend_summary(console, DummyDelta())
    output5 = out.getvalue()
    assert "Previous Score:" in output5
    assert "Stable" in output5
