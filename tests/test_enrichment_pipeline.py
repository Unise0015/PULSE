import pytest
from unittest.mock import MagicMock, patch
from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.services.enrichment_pipeline import (
    EnrichmentPipeline, EnrichmentResult, EnrichmentMetrics, BaseEnricher,
    VersionEnricher, OSVEnricher, NVDEnricher, EPSSEnricher, MITREEnricher,
    KEVEnricher, RiskEnricher, ExploitEnricher, AttackPathEnricher,
    compute_packages_fingerprint
)

def test_compute_packages_fingerprint():
    pkgs = [
        PackageInfo(name="requests", version="2.28.1", ecosystem="PyPI"),
        PackageInfo(name="urllib3", version="1.26.12", ecosystem="PyPI")
    ]
    fp = compute_packages_fingerprint(pkgs)
    assert len(fp) == 64  # SHA-256 length
    
    # Order independence
    fp_reverse = compute_packages_fingerprint(list(reversed(pkgs)))
    assert fp == fp_reverse

def test_calculate_attack_surface_score():
    finding1 = VulnerabilityFinding(
        package=PackageInfo(name="a", version="1.0.0", ecosystem="PyPI"),
        cve_id="CVE-2021-0001",
        cvss_score=8.0,
        cvss_severity="HIGH",
        epss_score=0.1,
        epss_percent="10%",
        kev_match=True,
        risk_heat_score=60,
        description="desc",
        fix_version=None,
        source="OSV",
        published_date=None,
        last_modified_date=None,
        nvd_url=""
    )
    finding2 = VulnerabilityFinding(
        package=PackageInfo(name="b", version="1.0.0", ecosystem="PyPI"),
        cve_id="CVE-2021-0002",
        cvss_score=4.0,
        cvss_severity="MEDIUM",
        epss_score=0.01,
        epss_percent="1%",
        kev_match=False,
        risk_heat_score=30,
        description="desc",
        fix_version=None,
        source="OSV",
        published_date=None,
        last_modified_date=None,
        nvd_url=""
    )
    
    # findings average risk = (60 + 30) // 2 = 45. KEV penalty = 10 for finding1. Total = 55.
    score = EnrichmentPipeline.calculate_attack_surface_score([finding1, finding2])
    assert score == 55

@patch("pulse.services.enrichment_pipeline.VersionIntelligenceService")
def test_version_enricher(mock_service_cls):
    mock_service = mock_service_cls.return_value
    enricher = VersionEnricher()
    
    pkgs = [PackageInfo(name="requests", version="2.28.1", ecosystem="PyPI")]
    res = EnrichmentResult(findings=[], attack_paths=[], packages=pkgs, metrics=EnrichmentMetrics())
    
    enricher.enrich(res)
    mock_service.enrich_packages.assert_called_once_with(pkgs)

@patch("pulse.services.enrichment_pipeline.OSVProvider")
def test_osv_enricher(mock_osv_cls):
    mock_osv = mock_osv_cls.return_value
    mock_finding = MagicMock(spec=VulnerabilityFinding)
    mock_finding.description = "Some description"
    mock_osv.lookup_packages.return_value = [mock_finding]
    
    enricher = OSVEnricher()
    pkgs = [PackageInfo(name="requests", version="2.28.1", ecosystem="PyPI")]
    res = EnrichmentResult(findings=[], attack_paths=[], packages=pkgs, metrics=EnrichmentMetrics())
    
    enricher.enrich(res)
    assert len(res.findings) == 1
    assert res.findings[0].summary == "Some description"
    assert res.metrics.osv_matches == 1

def test_pipeline_configurable_stages():
    class DummyEnricher(BaseEnricher):
        def enrich(self, data: EnrichmentResult, progress=None, context=None) -> None:
            data.findings.append("dummy")

    pipeline = EnrichmentPipeline(stages=[DummyEnricher])
    res = pipeline.run(packages=[])
    
    assert res.findings == ["dummy"]
    assert res.metrics.elapsed_ms >= 0

def test_pipeline_independent_degradation():
    class SuccessEnricher(BaseEnricher):
        def enrich(self, data: EnrichmentResult, progress=None, context=None) -> None:
            data.findings.append("success")

    class CrashEnricher(BaseEnricher):
        def enrich(self, data: EnrichmentResult, progress=None, context=None) -> None:
            raise RuntimeError("Something crashed")

    pipeline = EnrichmentPipeline(stages=[SuccessEnricher, CrashEnricher, SuccessEnricher])
    res = pipeline.run(packages=[])
    
    assert res.findings == ["success", "success"]
    assert len(res.warnings) == 1
    assert "Enrichment stage CrashEnricher failed: Something crashed" in res.warnings[0]
