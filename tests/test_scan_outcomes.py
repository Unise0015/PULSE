import io
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from pulse.domain.models import PackageInfo, ScanResult, PluginDiagnostics, PluginExecutionStatus
from pulse.services.enrichment_pipeline import EnrichmentPipeline, OSVEnricher
from pulse.services.package_service import PackageService
from pulse.history import HistoryService
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.context import ReportContext
from pulse.reporting.renderers import HTMLRenderer, JSONRenderer, MarkdownRenderer, TextRenderer
from pulse.ui import print_security_summary


class FailedLookup:
    def enrich(self, *args):
        raise RuntimeError("intelligence lookup failed")


def make_scan(**kwargs):
    return ScanResult(timestamp=datetime.now(), hostname="fixture", tool_version="4.0.0",
                      packages_scanned=1, attack_surface_score=0, **kwargs)


@pytest.mark.parametrize("discovery", [False, True])
def test_failure_survives_scan_history_and_all_exports(monkeypatch, discovery):
    pkg = PackageInfo(name="requests", version="2.0.0", ecosystem="PyPI")
    pipeline = EnrichmentPipeline(stages=[FailedLookup])
    module = "pulse.services.scan_service" if discovery else "pulse.services.package_service"
    monkeypatch.setattr(module + ".EnrichmentPipeline", lambda: pipeline)
    # Static score computation is also used by the scan entry point.
    factory = lambda: pipeline
    factory.calculate_attack_surface_score = EnrichmentPipeline.calculate_attack_surface_score
    monkeypatch.setattr(module + ".EnrichmentPipeline", factory)
    monkeypatch.setattr(module + ".SecurityAdvisor", Mock())
    monkeypatch.setattr("pulse.version_intelligence.recommendation_engine.populate_scan_recommendations", lambda scan: None)
    if discovery:
        from pulse.services.scan_service import ScanService
        result = SimpleNamespace(packages=[pkg], dependency_edges=[], diagnostics=PluginDiagnostics(status=PluginExecutionStatus.SUCCESS))
        plugin = SimpleNamespace(manifest=SimpleNamespace(id="python", name="Python"), discover=lambda ctx: result)
        monkeypatch.setattr("pulse.services.scan_service.registry.detect", lambda ctx: [plugin])
        scan = ScanService().run(Console(file=io.StringIO()))
    else:
        scan = PackageService().run(Console(file=io.StringIO()), [pkg])
    assert "intelligence lookup failed" in scan.warnings[0]
    console = Console(file=io.StringIO())
    print_security_summary(console, scan)
    assert "Assessment incomplete" in console.file.getvalue()
    assert "No known vulnerabilities detected" not in console.file.getvalue()

    history = HistoryService()
    loaded = history.get_scan_by_id(history.save_scan(scan))
    assert loaded.warnings == scan.warnings
    assert history.get_scan_runs()[0]["scan_integrity"] == "LOW"
    assert history.get_posture_delta(scan) is None
    assert history.get_posture_delta(make_scan()) is None
    report = ReportBuilder.build(ReportContext(scan_result=loaded, scan_id="fixture"))
    assert not report.executive_summary.assessment_complete
    for renderer in (HTMLRenderer(), MarkdownRenderer(), TextRenderer()):
        text = renderer.render(report)
        assert "Assessment incomplete" in text
        assert "intelligence lookup failed" in text
        assert "No known vulnerabilities detected" not in text
    data = json.loads(JSONRenderer().render(report))
    assert data["warnings"] == scan.warnings
    assert data["executive_summary"]["assessment_complete"] is False


def test_successful_empty_result_is_distinct_from_failure():
    scan = make_scan()
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="complete"))
    assert report.executive_summary.assessment_complete
    assert "No known vulnerabilities detected" in TextRenderer().render(report)
    assert not EnrichmentPipeline(stages=[]).run([]).warnings


def test_discovery_failure_is_completion_evidence():
    scan = make_scan(plugin_diagnostics={"python": PluginDiagnostics(status=PluginExecutionStatus.FAILED)})
    assert "python: discovery failed" in scan.assessment_warnings


def test_osv_progress_accepts_task_zero_without_name_error(monkeypatch):
    provider = Mock(warnings=[])
    provider.lookup_packages.return_value = []
    monkeypatch.setattr("pulse.services.enrichment_pipeline.OSVProvider", lambda: provider)
    resolver = Mock()
    resolver.resolve.return_value = None
    monkeypatch.setattr("pulse.enrichment.nvd.cpe_resolver.TieredCPEResolver", lambda: resolver)
    progress = Mock()
    progress.add_task.return_value = 0
    result = EnrichmentPipeline(stages=[OSVEnricher]).run(
        [PackageInfo(name="fixture", version="1.0", ecosystem="PyPI")], progress=progress)
    assert result.warnings == []
    provider.lookup_packages.assert_called_once()
    assert provider.lookup_packages.call_args.kwargs["task_id"] == 0
    provider.client.close.assert_called_once()


def test_html_escapes_untrusted_target_and_warnings():
    payload = '<script>alert("fixture")</script>'
    scan = make_scan(target_id=payload, warnings=[payload])
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="escape"))
    text = HTMLRenderer().render(report)
    assert payload not in text
    assert "&lt;script&gt;" in text


def test_legacy_history_does_not_invent_verified_coverage():
    import sqlite3
    history = HistoryService()
    scan_id = history.save_scan(make_scan())
    with sqlite3.connect(history.db_path) as conn:
        conn.execute("UPDATE scan_runs SET warnings_json = NULL, scan_integrity = NULL WHERE id = ?", (scan_id,))
    assert history.get_scan_by_id(scan_id).assessment_warnings
    assert history.get_scan_runs()[0]["scan_integrity"] == "UNKNOWN"


@pytest.mark.parametrize("url", ["javascript:alert(1)", "http://[", "https:///missing-host"])
def test_html_does_not_render_executable_reference_urls(url):
    from pulse.domain.models import VulnerabilityFinding
    scan = make_scan(findings=[VulnerabilityFinding(
        package=PackageInfo(name="fixture", version="1", ecosystem="npm"),
        cve_id="CVE-2025-12345", nvd_url=url)])
    text = HTMLRenderer().render(ReportBuilder.build(ReportContext(scan_result=scan, scan_id="links")))
    assert f'href="{url}"' not in text


def test_detection_only_website_does_not_report_complete_coverage():
    from pulse.domain.models import WebsiteAssessment, CorrelationStatus
    scan = make_scan(website_assessment=WebsiteAssessment(
        url="https://fixture.invalid", correlation_status=CorrelationStatus.COMPLETED))
    report = ReportBuilder.build(ReportContext(scan_result=scan, scan_id="detection-only"))
    assert not report.executive_summary.assessment_complete
    assert "No website technologies completed vulnerability correlation" in report.warnings


@pytest.mark.parametrize("complete", [True, False])
def test_website_history_preserves_recorded_coverage(complete):
    from pulse.domain.models import WebsiteAssessment, CorrelationStatus
    completed_at = datetime(2026, 10, 7, 12, 0)
    assessment = WebsiteAssessment(url="https://fixture.invalid",
        correlation_status=CorrelationStatus.COMPLETED if complete else CorrelationStatus.PARTIAL,
        correlated_technologies=1, failed_technologies=0 if complete else 1,
        correlation_completed_at=completed_at)
    scan = make_scan(target_type="website", target_id=assessment.url, website_assessment=assessment,
                     warnings=[] if complete else ["OSV unavailable"])
    history = HistoryService()
    loaded = history.get_scan_by_id(history.save_scan(scan))
    assert loaded.assessment_warnings == scan.assessment_warnings
    assert loaded.website_assessment.correlation_status == assessment.correlation_status
    assert loaded.website_assessment.correlated_technologies == 1
    assert loaded.website_assessment.correlation_completed_at == completed_at
    report = ReportBuilder.build(ReportContext(scan_result=loaded, scan_id="history"))
    assert report.executive_summary.assessment_complete is complete


def test_legacy_website_state_remains_unknown():
    import sqlite3
    from pulse.domain.models import WebsiteAssessment, CorrelationStatus
    scan = make_scan(target_type="website", website_assessment=WebsiteAssessment(
        url="https://fixture.invalid", correlation_status=CorrelationStatus.COMPLETED, correlated_technologies=1))
    history = HistoryService()
    scan_id = history.save_scan(scan)
    with sqlite3.connect(history.db_path) as conn:
        conn.execute("UPDATE scan_runs SET website_state_json = NULL WHERE id = ?", (scan_id,))
    loaded = history.get_scan_by_id(scan_id)
    assert "Website correlation state was not recorded or could not be read" in loaded.assessment_warnings


def test_database_migration_preserves_existing_scan(tmp_path):
    import sqlite3
    from pulse.history.db import init_db

    legacy_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy_path) as conn:
        conn.execute("""CREATE TABLE scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, hostname TEXT,
            tool_version TEXT, attack_surface_score INTEGER,
            scan_duration_seconds REAL, packages_scanned INTEGER,
            vulnerabilities_found INTEGER, kev_matches INTEGER
        )""")
        conn.execute("""INSERT INTO scan_runs VALUES
            (1, '2026-10-07 12:00:00', 'fixture', '4.0.0', 0, 1.0, 1, 0, 0)""")
    init_db(legacy_path)
    init_db(legacy_path)  # Startup migrations must also be safe to repeat.
    with sqlite3.connect(legacy_path) as conn:
        assert conn.execute("SELECT hostname, website_state_json FROM scan_runs WHERE id = 1").fetchone() == ("fixture", None)
    history = HistoryService()
    history.db_path = legacy_path
    loaded = history.get_scan_by_id(1)
    assert loaded.hostname == "fixture"
    assert loaded.assessment_warnings  # Legacy coverage must remain unknown.
