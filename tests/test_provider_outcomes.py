import io
from datetime import datetime
from unittest.mock import Mock

import httpx
import pytest
from rich.console import Console

from pulse.domain.models import PackageInfo, VulnerabilityFinding, ScanResult, WebsiteAssessment, TechnologyFingerprint, CorrelationStatus
from pulse.services.enrichment_pipeline import EnrichmentPipeline, NVDEnricher, EPSSEnricher, KEVEnricher
from pulse.services.website_service import WebsiteService
from pulse.vulnerability.nvd_provider import NVDProvider
from pulse.vulnerability.threat_intel import EPSSProvider, KEVProvider
from pulse.enrichment.nvd.correlator import NVDCorrelationEngine
from pulse.correlation.models import CPECandidate, CorrelationResult, ResolverMatchType
from pulse.state import AppState


def finding():
    return VulnerabilityFinding(package=PackageInfo(name="fixture", version="1.0", ecosystem="PyPI"),
                                cve_id="CVE-2025-12345", source="OSV")


@pytest.mark.parametrize("provider_type,stage", [(NVDProvider, NVDEnricher), (EPSSProvider, EPSSEnricher), (KEVProvider, KEVEnricher)])
@pytest.mark.parametrize("offline", [False, True])
def test_unavailable_enrichment_preserves_findings_and_warns(monkeypatch, provider_type, stage, offline):
    provider = provider_type()
    provider.client.close()
    requests = []
    def unavailable(request):
        requests.append(request)
        return httpx.Response(503)
    provider.client = httpx.Client(transport=httpx.MockTransport(unavailable))
    monkeypatch.setattr(AppState, "OFFLINE_MODE", offline)
    monkeypatch.setattr("pulse.services.enrichment_pipeline." + provider_type.__name__, lambda: provider)
    vuln = finding()
    class Seed:
        def enrich(self, data, *args):
            data.findings.append(vuln)
    result = EnrichmentPipeline(stages=[Seed, stage]).run([vuln.package])
    assert result.findings == [vuln]
    assert result.warnings
    assert provider.client.is_closed
    assert bool(requests) is not offline


def test_nvd_correlation_failure_is_not_clean_result(monkeypatch):
    engine = NVDCorrelationEngine()
    try:
        monkeypatch.setattr(engine.cache, "get", lambda *args: None)
        monkeypatch.setattr(engine.provider, "fetch_cves_by_cpe", lambda *args: None)
        candidate = CPECandidate(cpe_template="cpe:2.3:a:fixture:fixture:*:*:*:*:*:*:*:*",
            detected_version="1.0", resolved_cpe=None, confidence=100, source="fixture",
            vendor="fixture", product="fixture", exact_version_match=True, match_type=ResolverMatchType.EXACT)
        result = CorrelationResult(technology="fixture", inventory_technology_key="fixture",
            candidates=[candidate], selected_candidate=candidate, resolution_confidence=100)
        findings, _ = engine.correlate([result])
        assert findings == []
        assert engine.warnings == ["NVD correlation unavailable for fixture"]
    finally:
        engine.provider.close()


def test_website_keeps_incomplete_correlation_state(monkeypatch):
    website = WebsiteService()
    tech = TechnologyFingerprint(name="AngularJS", version="1.8.2", category="Framework", confidence=100)
    scan = ScanResult(timestamp=datetime.now(), hostname="fixture", tool_version="4.0.0", packages_scanned=0,
                      attack_surface_score=0, target_type="website", website_assessment=WebsiteAssessment(
                          url="https://fixture.invalid", technologies=[tech]))
    monkeypatch.setattr(website, "_correlate_packages", lambda *args: ([], [], [], ["OSV unavailable"]))
    monkeypatch.setattr("pulse.version_intelligence.recommendation_engine.populate_scan_recommendations", lambda scan: None)
    monkeypatch.setattr("pulse.services.website_service.ReportService.create_scan_report", Mock())
    website.analyze_technologies(Console(file=io.StringIO()), scan)
    assert scan.website_assessment.correlation_status == CorrelationStatus.PARTIAL
    assert scan.website_assessment.technology_correlation_results["AngularJS"].correlation_status == "CORRELATION_UNAVAILABLE"
    assert "OSV unavailable" in scan.assessment_warnings


@pytest.mark.parametrize("status,body,expected", [(404, {}, None), (200, {}, None), (200, {"vulnerabilities": []}, [])])
def test_nvd_cpe_empty_success_is_distinct_from_bad_response(status, body, expected):
    from pulse.enrichment.nvd.provider import NVDCPEProvider
    provider = NVDCPEProvider()
    provider.client.close()
    provider.client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status, json=body)))
    provider.delay_between_reqs = 0
    try:
        assert provider.fetch_cves_by_cpe("cpe:2.3:a:fixture:fixture:1:*:*:*:*:*:*:*") == expected
    finally:
        provider.close()
