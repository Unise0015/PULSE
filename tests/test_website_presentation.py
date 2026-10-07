"""Website UI regressions; conftest.isolated_environment isolates DB paths and blocks live sockets for every test."""

import io
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from pulse.domain.models import (
    CorrelationStatus, FindingSourceType, PackageInfo, ScanResult, SecurityHeaderStatus,
    TechnologyCorrelationResult, TechnologyFingerprint, VulnerabilityFinding, WebsiteAssessment,
)
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.context import ReportContext
from pulse.reporting.renderers import HTMLRenderer, JSONRenderer, MarkdownRenderer, TextRenderer
from pulse.services.website_service import WebsiteService
from pulse.ui import print_technologies_view, print_website_assessment_summary, print_security_headers_view
from pulse.website.acquisition import normalize_website_url
from pulse.website.presentation import technology_views


def make_scan(**kwargs):
    return ScanResult(timestamp=datetime(2026, 10, 7), hostname="fixture", tool_version="4.0.0",
                      packages_scanned=0, attack_surface_score=0, target_type="website",
                      website_assessment=WebsiteAssessment(url="https://fixture.invalid", **kwargs))


def technology(name="Angular", version="17.0.0", **kwargs):
    return TechnologyFingerprint(name=name, version=version, category="Framework", confidence=95, **kwargs)


def test_rendering_never_resolves_or_claims_unchecked_technology_is_clean(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Rendering must not resolve technology identities")
    monkeypatch.setattr("pulse.website.capability.evaluate_correlation_eligibility", forbidden)
    scan = make_scan(technologies=[technology()], correlation_status=CorrelationStatus.COMPLETED,
                     correlated_technologies=1)
    console = Console(file=io.StringIO(), width=180)
    print_website_assessment_summary(console, scan)
    print_technologies_view(console, scan)
    output = console.file.getvalue()
    assert "Not checked" in output
    assert "With recorded results: 0" in output
    assert "Clean" not in output
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="fixture"))
    for renderer in (HTMLRenderer(), MarkdownRenderer(), TextRenderer()):
        output = renderer.render(report)
        assert "Not checked" in output and "Not established" in output
    payload = json.loads(JSONRenderer().render(report))
    section = next(s for s in payload["sections"] if s["name"] == "Website Assessment")
    assert section["technologies"][0]["correlated"] is False


def test_alias_findings_use_recorded_technology_mapping():
    finding = VulnerabilityFinding(package=PackageInfo(name="@angular/core", version="17.0.0", ecosystem="npm"),
                                   cve_id="CVE-2026-1234", source_asset="Angular", source_type=FindingSourceType.WEBSITE, cvss_severity="HIGH")
    scan = make_scan(technologies=[technology()])
    scan.findings = [finding]
    row = technology_views(scan)[0]
    assert row.findings == [finding]
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="fixture"))
    assert report.sections[0].technologies[0].vulnerability_count == 1


@pytest.mark.parametrize("status,expected,checked", [
    ("NO_KNOWN_VULNERABILITIES", "No known vulnerabilities", True),
    ("CORRELATION_UNAVAILABLE", "Check incomplete", False),
    ("VULNERABILITIES_FOUND", "Check incomplete", False),
])
def test_recorded_empty_results_are_honest_and_do_not_crash(status, expected, checked):
    scan = make_scan(technologies=[technology()], correlation_status=CorrelationStatus.PARTIAL,
                     technology_correlation_results={"Angular": TechnologyCorrelationResult(
                         technology_name="Angular", correlation_status=status)})
    row = technology_views(scan)[0]
    assert (row.label, row.checked) == (expected, checked)
    console = Console(file=io.StringIO(), width=180)
    print_technologies_view(console, scan)
    assert expected in console.file.getvalue()


def test_untrusted_markup_cycles_and_orphans_render_safely():
    name = "[bold]Literal[/bold]"
    scan = make_scan(technologies=[technology(name, children=["Second"], parent="Second"),
                                  technology("Second", children=[name], parent=name),
                                  technology("Orphan", parent="Absent")],
                     security_headers=[SecurityHeaderStatus("X-Header", "Missing", "[bold]value[/bold]")])
    console = Console(file=io.StringIO(), width=180)
    print_website_assessment_summary(console, scan)
    print_technologies_view(console, scan)
    print_security_headers_view(console, scan)
    output = console.file.getvalue()
    assert name in output and "[bold]value[/bold]" in output and "Orphan" in output
    assert output.count("No detailed evidence recorded") == 3


def test_unavailable_headers_have_explicit_empty_state():
    scan = make_scan(status="ERROR", status_code=0)
    console = Console(file=io.StringIO(), width=180)
    print_security_headers_view(console, scan)
    print_website_assessment_summary(console, scan)
    assert "not assessed" in console.file.getvalue()
    assert "No response" in console.file.getvalue()


@pytest.mark.parametrize("raw,expected", [
    (" example.com/path ", "https://example.com/path"),
    (" HTTPS://example.com ", "HTTPS://example.com"),
    ("localhost:8080/path", "https://localhost:8080/path"),
    ("//example.com", "https://example.com"),
    ("ftp://example.com", "ftp://example.com"),
    ("file:/tmp/test", "file:/tmp/test"),
    ("   ", ""),
])
def test_url_normalization_preserves_explicit_schemes(raw, expected):
    assert normalize_website_url(raw) == expected


def test_website_menu_exports_current_scan_and_hides_invalid_correlation(monkeypatch):
    from pulse import cli
    scan = make_scan(status="ERROR", status_code=0)
    choices_seen = []
    answers = iter(["Export Report", "Back to Main Menu"])
    def select(prompt, choices):
        choices_seen.extend(choices)
        return SimpleNamespace(ask=lambda: next(answers))
    monkeypatch.setattr(cli.questionary, "select", select)
    export = Mock()
    monkeypatch.setattr(cli, "export_workflow", export)
    cli.website_post_scan_menu(scan)
    export.assert_called_once_with(scan)
    assert not any("Correlat" in item for item in choices_seen)


def test_partial_website_menu_offers_retry(monkeypatch):
    from pulse import cli
    scan = make_scan(technologies=[technology()], correlation_status=CorrelationStatus.PARTIAL)
    select = Mock(return_value=SimpleNamespace(ask=lambda: None))
    monkeypatch.setattr(cli.questionary, "select", select)
    cli.website_post_scan_menu(scan)
    assert "Retry Correlation" in select.call_args.kwargs["choices"]


def test_correlation_failure_recovers_with_explicit_failed_state(monkeypatch):
    scan = make_scan(technologies=[technology()])
    service = WebsiteService()
    monkeypatch.setattr(service, "_resolve_package_identities", Mock(side_effect=RuntimeError("fixture")))
    assert service.analyze_technologies(Console(file=io.StringIO()), scan) is scan
    assert scan.website_assessment.correlation_status == CorrelationStatus.FAILED
    assert any("Website correlation failed" in w for w in scan.assessment_warnings)
    assert not technology_views(scan)[0].checked


@pytest.mark.parametrize("state,techs", [("ERROR", [technology()]), ("OFFLINE", [technology()]), ("OK", [])])
def test_correlation_does_not_run_without_usable_detection(monkeypatch, state, techs):
    scan = make_scan(status=state, technologies=techs)
    service = WebsiteService()
    run = Mock()
    monkeypatch.setattr(service, "_analyze_technologies", run)
    service.analyze_technologies(Console(file=io.StringIO()), scan)
    run.assert_not_called()


def test_website_report_escapes_header_and_technology_evidence():
    scan = make_scan(technologies=[technology('<script>alert(1)</script>')],
                     security_headers=[SecurityHeaderStatus("CSP", "Weak", '<img src=x onerror="alert(1)">')])
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="fixture"))
    html = HTMLRenderer().render(report)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert '<img src=x' not in html
    assert "Security headers" in html
    for renderer in (MarkdownRenderer(), TextRenderer()):
        assert "CSP: Weak" in renderer.render(report)


def test_successful_retry_replaces_old_failure_warnings(monkeypatch):
    scan = make_scan(technologies=[technology("AngularJS", "1.8.2")], warnings=["Page was truncated"])
    scan._reconstructing = True
    service = WebsiteService()
    monkeypatch.setattr("pulse.version_intelligence.recommendation_engine.populate_scan_recommendations", lambda scan: None)
    monkeypatch.setattr(service, "_correlate_packages", Mock(side_effect=[
        ([], [], [], ["OSV unavailable"]), ([], [], [], [])]))
    console = Console(file=io.StringIO())
    service.analyze_technologies(console, scan)
    assert "OSV unavailable" in scan.assessment_warnings
    service.analyze_technologies(console, scan)
    assert scan.website_assessment.correlation_status == CorrelationStatus.COMPLETED
    assert "OSV unavailable" not in scan.assessment_warnings
    assert "Page was truncated" in scan.assessment_warnings
    assert technology_views(scan)[0].checked


def test_website_history_restores_headers_redirect_and_per_technology_results(tmp_path):
    from pulse.history import HistoryService
    scan = make_scan(technologies=[technology()], security_headers=[SecurityHeaderStatus("CSP", "Missing", "Set a policy")],
                     correlation_status=CorrelationStatus.COMPLETED, correlated_technologies=1,
                     technology_correlation_results={"Angular": TechnologyCorrelationResult(
                         technology_name="Angular", correlation_status="NO_KNOWN_VULNERABILITIES")})
    scan.target_id = "https://start.invalid"
    history = HistoryService()
    assert history.db_path.parent == tmp_path
    loaded = history.get_scan_by_id(history.save_scan(scan))
    assert loaded.website_assessment.url == "https://fixture.invalid"
    assert loaded.website_assessment.security_headers == scan.website_assessment.security_headers
    assert technology_views(loaded)[0].label == "No known vulnerabilities"
    assert loaded.assessment_warnings == scan.assessment_warnings


def test_website_history_restores_aliased_findings():
    from pulse.history import HistoryService
    finding = VulnerabilityFinding(package=PackageInfo(name="@angular/core", version="17.0.0", ecosystem="npm"),
                                   cve_id="CVE-2026-1234", source_asset="Angular", source_type=FindingSourceType.WEBSITE, cvss_severity="HIGH")
    scan = make_scan(technologies=[technology()], correlation_status=CorrelationStatus.COMPLETED,
                     correlated_technologies=1, technology_correlation_results={"Angular": TechnologyCorrelationResult(
                         technology_name="Angular", correlation_status="VULNERABILITIES_FOUND", vulnerabilities=[finding])})
    scan.findings = [finding]
    history = HistoryService()
    loaded = history.get_scan_by_id(history.save_scan(scan))
    assert len(technology_views(loaded)[0].findings) == 1


def test_opening_history_does_not_rerun_correlation(monkeypatch):
    from pulse.history import HistoryService
    from pulse.scanner import ScannerOrchestrator
    scan = make_scan(technologies=[technology()])
    history = HistoryService()
    scan_id = history.save_scan(scan)
    correlate = Mock(side_effect=AssertionError("Opening history must not run providers"))
    monkeypatch.setattr(WebsiteService, "analyze_technologies", correlate)
    loaded = ScannerOrchestrator().get_historical_scan(scan_id)
    correlate.assert_not_called()
    assert loaded.website_assessment.correlation_status == CorrelationStatus.NOT_RUN


def test_failed_retry_clears_previous_scan_results(monkeypatch):
    finding = VulnerabilityFinding(package=PackageInfo(name="angular", version="17.0.0", ecosystem="npm"),
                                   cve_id="CVE-2026-1234", source_asset="Angular")
    scan = make_scan(technologies=[technology()], correlation_status=CorrelationStatus.COMPLETED,
                     correlated_technologies=1, technology_correlation_results={"Angular": TechnologyCorrelationResult(
                         technology_name="Angular", correlation_status="VULNERABILITIES_FOUND", vulnerabilities=[finding])})
    scan.findings = [finding]
    scan.attack_paths = [object()]
    scan.packages_scanned = 1
    scan.attack_surface_score = 80
    scan.upgrade_recommendations = {"angular": object()}
    scan.website_assessment.technology_eligibilities = {"angular": object()}
    service = WebsiteService()
    monkeypatch.setattr(service, "_resolve_package_identities", Mock(side_effect=RuntimeError("fixture retry failure")))
    service.analyze_technologies(Console(file=io.StringIO()), scan)
    assert not scan.website_assessment.technology_eligibilities
    assert not scan.findings and not scan.attack_paths and not scan.upgrade_recommendations
    assert scan.packages_scanned == 0 and scan.attack_surface_score == 0
    assert scan.website_assessment.correlation_status == CorrelationStatus.FAILED
    assert not technology_views(scan)[0].checked
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="retry"))
    assert not report.findings and not report.executive_summary.assessment_complete


def test_history_links_findings_after_deduplication():
    from pulse.history import HistoryService
    primary = VulnerabilityFinding(package=PackageInfo(name="@angular/core", version="17.0.0", ecosystem="npm"),
                                   cve_id="CVE-2026-1234", source_type=FindingSourceType.WEBSITE)
    duplicate = VulnerabilityFinding(package=PackageInfo(name="@Angular/Core", version="17.0.0", ecosystem="CPE"),
                                     cve_id="cve-2026-1234", source_type=FindingSourceType.WEBSITE)
    scan = make_scan(technologies=[technology()], correlation_status=CorrelationStatus.COMPLETED,
                     correlated_technologies=1, technology_correlation_results={"Angular": TechnologyCorrelationResult(
                         technology_name="Angular", correlation_status="VULNERABILITIES_FOUND", vulnerabilities=[duplicate])})
    scan.findings = [primary, duplicate]
    history = HistoryService()
    loaded = history.get_scan_by_id(history.save_scan(scan))
    assert len(loaded.findings) == 1
    assert technology_views(loaded)[0].findings == loaded.findings
    assert not any("could not be restored" in warning for warning in loaded.assessment_warnings)


def test_malformed_history_finding_keys_do_not_hide_subsequent_results():
    import sqlite3
    from pulse.history import HistoryService
    scan = make_scan(technologies=[technology(), technology("Second")],
                     correlation_status=CorrelationStatus.COMPLETED, correlated_technologies=2,
                     technology_correlation_results={name: TechnologyCorrelationResult(
                         technology_name=name, correlation_status="NO_KNOWN_VULNERABILITIES")
                         for name in ("Angular", "Second")})
    history = HistoryService()
    scan_id = history.save_scan(scan)
    with sqlite3.connect(history.db_path) as conn:
        state = json.loads(conn.execute("SELECT website_state_json FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()[0])
        state["technology_results"]["Angular"]["finding_keys"] = [None, ["short"], "abcd", ["npm", {}, "17.0.0", "CVE-2026-1234"]]
        conn.execute("UPDATE scan_runs SET website_state_json = ? WHERE id = ?", (json.dumps(state), scan_id))
    loaded = history.get_scan_by_id(scan_id)
    assert loaded.website_assessment.technology_correlation_results["Second"].correlation_status == "NO_KNOWN_VULNERABILITIES"
    assert any("could not be restored" in w for w in loaded.assessment_warnings)


@pytest.mark.parametrize("bad_result", [None, [], "invalid", {"technology_name": []}, {"correlation_status": None}])
def test_malformed_history_result_does_not_interrupt_remaining_records(bad_result):
    import sqlite3
    from pulse.history import HistoryService
    scan = make_scan(technologies=[technology(), technology("Second")],
                     correlation_status=CorrelationStatus.COMPLETED, correlated_technologies=2,
                     technology_correlation_results={name: TechnologyCorrelationResult(
                         technology_name=name, correlation_status="NO_KNOWN_VULNERABILITIES")
                         for name in ("Angular", "Second")})
    scan.warnings = ["Preserved scan warning"]
    history = HistoryService()
    scan_id = history.save_scan(scan)
    with sqlite3.connect(history.db_path) as conn:
        state = json.loads(conn.execute("SELECT website_state_json FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()[0])
        state["technology_results"]["Angular"] = bad_result
        # Fields from newer schemas must not break supported records.
        state["technology_results"]["Second"]["future_field"] = {"value": 1}
        conn.execute("UPDATE scan_runs SET website_state_json = ? WHERE id = ?", (json.dumps(state), scan_id))
    loaded = history.get_scan_by_id(scan_id)
    assert "Angular" not in loaded.website_assessment.technology_correlation_results
    assert loaded.website_assessment.technology_correlation_results["Second"].correlation_status == "NO_KNOWN_VULNERABILITIES"
    assert loaded.warnings == ["Preserved scan warning"]
    assert any("result for Angular could not be read" in w for w in loaded.assessment_warnings)
    assert not ReportBuilder.build(ReportContext(scan_result=loaded, scan_id="malformed")).executive_summary.assessment_complete


@pytest.mark.parametrize("field,value", [
    ("warnings", None), ("correlation_warnings", {}), ("scan_warnings", [None]),
    ("security_headers", None), ("security_headers", [{"header_name": "CSP", "status": 1}]),
    ("url", None), ("technology_results", []),
])
def test_malformed_website_metadata_stays_renderable(field, value):
    import sqlite3
    from pulse.history import HistoryService
    scan = make_scan(technologies=[technology()])
    history = HistoryService()
    scan_id = history.save_scan(scan)
    with sqlite3.connect(history.db_path) as conn:
        state = json.loads(conn.execute("SELECT website_state_json FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()[0])
        state[field] = value
        conn.execute("UPDATE scan_runs SET website_state_json = ? WHERE id = ?", (json.dumps(state), scan_id))
    loaded = history.get_scan_by_id(scan_id)
    assert any("could not be read" in w for w in loaded.assessment_warnings)
    print_security_headers_view(Console(file=io.StringIO()), loaded)
    report = ReportBuilder.build(ReportContext(scan_result=loaded, scan_id="malformed-metadata"))
    assert "Assessment incomplete" in HTMLRenderer().render(report)
