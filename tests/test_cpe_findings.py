import io
from types import SimpleNamespace
from unittest.mock import Mock

from rich.console import Console

from pulse.domain.models import PackageInfo, VulnerabilityFinding, TechnologyFingerprint
from pulse.enrichment.nvd.models import CorrelatedVulnerability, VersionMatchType
from pulse.services.enrichment_pipeline import EnrichmentPipeline, OSVEnricher
from pulse.services.website_service import WebsiteService


def correlated(version="2.0"):
    return CorrelatedVulnerability(cve_id="CVE-2025-22222", technology_name="fixture",
        source_cpe="cpe:2.3:a:fixture:fixture:*:*:*:*:*:*:*:*", matched_cpe=None,
        correlation_source="cpe:2.3:a:fixture:fixture", matched_version=version,
        version_match_type=VersionMatchType.EXACT, confidence=100, candidate_confidence=100)


def engine_fixture(monkeypatch):
    engine = Mock(warnings=[])
    engine.correlate.return_value = ([correlated()], None)
    monkeypatch.setattr("pulse.enrichment.nvd.correlator.NVDCorrelationEngine", lambda: engine)
    return engine


def test_nvd_fallback_keeps_the_correct_package_version(monkeypatch):
    packages = [PackageInfo(name="fixture", version=version, ecosystem="PyPI") for version in ("1.0", "2.0")]
    provider = Mock(warnings=[])
    provider.lookup_packages.return_value = [VulnerabilityFinding(package=packages[0], cve_id="CVE-2025-11111")]
    monkeypatch.setattr("pulse.services.enrichment_pipeline.OSVProvider", lambda: provider)
    resolver = Mock()
    resolver.resolve.return_value = SimpleNamespace(cpe_uri="cpe:2.3:a:fixture:fixture", confidence=100,
        source="fixture", vendor="fixture", product="fixture")
    monkeypatch.setattr("pulse.enrichment.nvd.cpe_resolver.TieredCPEResolver", lambda: resolver)
    engine_fixture(monkeypatch)
    result = EnrichmentPipeline(stages=[OSVEnricher]).run(packages)
    assert not result.warnings
    assert {(f.package.version, f.cve_id) for f in result.findings} == {
        ("1.0", "CVE-2025-11111"), ("2.0", "CVE-2025-22222")}
    resolver.resolve.assert_called_once_with("fixture", "PyPI")


def test_website_cpe_findings_use_matched_version(monkeypatch):
    engine_fixture(monkeypatch)
    tech = TechnologyFingerprint(name="fixture", version="2.0", category="Server", confidence=100)
    eligibility = SimpleNamespace(is_eligible=True, package_name=None, cpe_vendor="fixture", cpe_product="fixture")
    _, _, cpe_findings, warnings = WebsiteService()._correlate_packages(
        [], [tech], {"fixture": eligibility}, Console(file=io.StringIO()))
    assert not warnings
    assert len(cpe_findings) == 1
    assert cpe_findings[0].package.version == "2.0"
