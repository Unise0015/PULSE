from pulse.core.provider_health import (
    provider_tracker,
    ProviderHealth,
    ProviderStatus
)

import time

def test_provider_health_tracker_context_manager():
    provider_tracker.reset()

    with provider_tracker.track("OSV") as health:
        health.records_requested = 10
        health.records_enriched = 10
        health.cache_hits = 2
        time.sleep(0.005)

    all_health = provider_tracker.get_all_health()
    assert "OSV" in all_health
    osv_health = all_health["OSV"]
    assert osv_health.status == ProviderStatus.HEALTHY
    assert osv_health.duration_ms >= 0.0
    assert osv_health.records_enriched == 10


def test_provider_health_status_transitions():
    p = ProviderHealth(provider="NVD", records_requested=10, records_enriched=5)
    p.warnings.append("API rate limit hit")
    assert p.compute_status() == ProviderStatus.PARTIAL

    p_off = ProviderHealth(provider="NVD", records_requested=10, records_enriched=0, network_requests=1)
    p_off.warnings.append("Service offline 500")
    assert p_off.compute_status() == ProviderStatus.OFFLINE
