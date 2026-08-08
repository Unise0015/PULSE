import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from pulse.enrichment.nvd.models import CorrelatedVulnerability, VersionMatchType
from pulse.enrichment.threat_intel.models import ThreatIntelRecord, ThreatIntelMatchType
from pulse.enrichment.threat_intel.pipeline import ThreatIntelligencePipeline
from pulse.enrichment.threat_intel.cache import ThreatIntelCache


@pytest.fixture
def mock_vuln() -> CorrelatedVulnerability:
    return CorrelatedVulnerability(
        cve_id="CVE-2023-1234",
        technology_name="Test Tech",
        source_cpe="cpe:2.3:a:test:test",
        matched_cpe="cpe:2.3:a:test:test:1.0",
        correlation_source="test",
        matched_version="1.0",
        version_match_type=VersionMatchType.EXACT,
        confidence=100,
        candidate_confidence=100,
        cwe="CWE-79"
    )


@pytest.fixture
def pipeline(monkeypatch) -> ThreatIntelligencePipeline:
    # Clear out actual db initialization if any, or mock out adapters
    pipeline = ThreatIntelligencePipeline()
    
    # Mock EPSS Adapter
    pipeline.epss.adapter.get_scores = MagicMock(return_value={
        "CVE-2023-1234": {"score": 0.91, "percent": "99.7%"}
    })
    
    # Mock KEV Adapter
    pipeline.kev.adapter.get_catalog = MagicMock(return_value={
        "CVE-2023-1234": {"dateAdded": "2023-01-01"}
    })
    
    # Mock ATT&CK Mapper
    pipeline.attack.mapper.mapping = {
        "CWE-79": [
            {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": "High"}
        ]
    }
    
    # Use a real tempfile for sqlite cache to persist across connections
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    pipeline.cache.db_path = path
    pipeline.cache._ensure_table()
    
    yield pipeline
    
    # Cleanup
    try:
        os.unlink(path)
    except OSError:
        pass


def test_epss_enrichment(pipeline, mock_vuln):
    records, stats = pipeline.enrich([mock_vuln])
    assert len(records) == 1
    record = records[0]
    
    assert record.epss_score == 0.91
    assert record.epss_percentile == 99.7
    assert "EPSS" in record.enrichment_sources
    assert stats.epss_matches == 1


def test_kev_enrichment(pipeline, mock_vuln):
    records, stats = pipeline.enrich([mock_vuln])
    record = records[0]
    
    assert record.kev_listed is True
    assert "KEV" in record.enrichment_sources
    assert stats.kev_matches == 1


def test_attack_enrichment(pipeline, mock_vuln):
    records, stats = pipeline.enrich([mock_vuln])
    record = records[0]
    
    assert "T1190" in record.attack_techniques
    assert "Initial Access" in record.attack_tactics
    assert record.attack_match_type == ThreatIntelMatchType.DIRECT
    assert record.attack_confidence == 90
    assert "ATT&CK" in record.enrichment_sources
    assert stats.attack_matches == 1


def test_exploit_detection(pipeline, mock_vuln):
    records, stats = pipeline.enrich([mock_vuln])
    record = records[0]
    
    # Since it's in KEV, exploit is available
    assert record.exploit_available is True
    assert record.exploit_match_type == ThreatIntelMatchType.INFERRED
    assert "EXPLOIT" in record.enrichment_sources
    assert stats.exploit_matches == 1


def test_cache_validation(pipeline, mock_vuln):
    # First lookup, should not hit cache
    _, stats1 = pipeline.enrich([mock_vuln])
    assert stats1.cache_hits == 0
    
    # Second lookup, should hit cache
    _, stats2 = pipeline.enrich([mock_vuln])
    assert stats2.cache_hits == 1
    
    # Ensure data was deserialized properly
    assert stats2.epss_matches == 1
    assert stats2.kev_matches == 1
    assert stats2.attack_matches == 1
    assert stats2.exploit_matches == 1


def test_pipeline_statistics(pipeline, mock_vuln):
    # Process multiple vulns, some with data, some without
    mock_vuln2 = CorrelatedVulnerability(
        cve_id="CVE-NO-DATA",
        technology_name="Test Tech",
        source_cpe="cpe:2.3:a:test:test",
        matched_cpe="cpe:2.3:a:test:test:1.0",
        correlation_source="test",
        matched_version="1.0",
        version_match_type=VersionMatchType.EXACT,
        confidence=100,
        candidate_confidence=100,
        cwe="CWE-NO-DATA"
    )
    
    records, stats = pipeline.enrich([mock_vuln, mock_vuln2])
    
    assert stats.vulnerabilities_processed == 2
    assert stats.epss_matches == 1
    assert stats.kev_matches == 1
    assert stats.attack_matches == 1
    assert stats.unenriched_vulnerabilities == 1
