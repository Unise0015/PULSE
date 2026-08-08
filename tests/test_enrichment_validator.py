from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.core.provider_health import ProviderHealth, ProviderStatus
from pulse.core.enrichment_validator import (
    EnrichmentConsistencyValidator,
    ScanIntegrity,
    ValidationSummary
)

def test_scan_integrity_calculation_high():
    p_osv = ProviderHealth(provider="OSV", status=ProviderStatus.HEALTHY, records_requested=5, records_enriched=5)
    p_nvd = ProviderHealth(provider="NVD", status=ProviderStatus.HEALTHY, records_requested=5, records_enriched=5)
    health_map = {"OSV": p_osv, "NVD": p_nvd}

    summary = ValidationSummary(valid_cves_count=5, valid_cvss_count=5)
    integrity, reasons = EnrichmentConsistencyValidator.calculate_scan_integrity(health_map, summary, 5)

    assert integrity == ScanIntegrity.HIGH
    assert any("healthy" in r.lower() for r in reasons)


def test_scan_integrity_calculation_medium():
    p_osv = ProviderHealth(provider="OSV", status=ProviderStatus.HEALTHY, records_requested=5, records_enriched=5)
    p_nvd = ProviderHealth(provider="NVD", status=ProviderStatus.OFFLINE, records_requested=5, records_enriched=0)
    health_map = {"OSV": p_osv, "NVD": p_nvd}

    summary = ValidationSummary(valid_cves_count=5, valid_cvss_count=0)
    integrity, reasons = EnrichmentConsistencyValidator.calculate_scan_integrity(health_map, summary, 5)

    assert integrity == ScanIntegrity.MEDIUM
    assert any("unavailable" in r.lower() for r in reasons)


def test_scan_integrity_calculation_low_on_validation_failures():
    p_osv = ProviderHealth(provider="OSV", status=ProviderStatus.HEALTHY, records_requested=5, records_enriched=5)
    health_map = {"OSV": p_osv}

    summary = ValidationSummary(valid_cves_count=4, invalid_cve_count=1)
    integrity, reasons = EnrichmentConsistencyValidator.calculate_scan_integrity(health_map, summary, 5)

    assert integrity == ScanIntegrity.LOW
    assert any("validation failure" in r.lower() for r in reasons)
