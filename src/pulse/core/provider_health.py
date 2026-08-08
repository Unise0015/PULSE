import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class ProviderStatus(str, Enum):
    HEALTHY = "HEALTHY"
    PARTIAL = "PARTIAL"
    CACHE_ONLY = "CACHE_ONLY"
    OFFLINE = "OFFLINE"
    ERROR = "ERROR"

@dataclass
class ProviderHealth:
    """Telemetry metrics tracking execution health and statistics for a single intelligence provider."""
    provider: str
    status: ProviderStatus = ProviderStatus.HEALTHY
    cache_used: bool = False
    cache_hits: int = 0
    cache_misses: int = 0
    retry_count: int = 0
    records_requested: int = 0
    records_received: int = 0
    records_enriched: int = 0
    records_rejected: int = 0
    duplicates_removed: int = 0
    network_requests: int = 0
    duration_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)

    def compute_status(self) -> ProviderStatus:
        """Derive provider status deterministically from metrics and warnings."""
        if self.status == ProviderStatus.ERROR or self.status == ProviderStatus.OFFLINE:
            return self.status

        if self.records_requested > 0:
            if self.records_enriched == 0 and self.cache_hits == 0 and self.network_requests > 0:
                if any("unavailable" in w.lower() or "offline" in w.lower() or "500" in w for w in self.warnings):
                    return ProviderStatus.OFFLINE
                return ProviderStatus.ERROR
            if self.records_enriched < self.records_requested or len(self.warnings) > 0:
                return ProviderStatus.PARTIAL
        
        if self.cache_used and self.network_requests == 0:
            return ProviderStatus.CACHE_ONLY

        return ProviderStatus.HEALTHY


class ProviderTrackerRegistry:
    """Thread-safe global tracker registry for provider telemetry across scan pipeline."""

    def __init__(self):
        self._providers: Dict[str, ProviderHealth] = {}

    def get_health(self, provider_name: str) -> ProviderHealth:
        if provider_name not in self._providers:
            self._providers[provider_name] = ProviderHealth(provider=provider_name)
        return self._providers[provider_name]

    def get_all_health(self) -> Dict[str, ProviderHealth]:
        for health in self._providers.values():
            health.status = health.compute_status()
        return dict(self._providers)

    def reset(self) -> None:
        self._providers.clear()

    @contextmanager
    def track(self, provider_name: str):
        health = self.get_health(provider_name)
        start_time = time.perf_counter()
        try:
            yield health
        except Exception as e:
            health.status = ProviderStatus.ERROR
            health.warnings.append(f"Unexpected provider exception: {type(e).__name__}: {e}")
            logger.error(f"Provider {provider_name} encountered error: {e}", exc_info=True)
            raise
        finally:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            health.duration_ms += round(elapsed, 2)
            health.status = health.compute_status()


# Global tracker instance
provider_tracker = ProviderTrackerRegistry()
