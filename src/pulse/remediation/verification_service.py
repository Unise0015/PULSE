import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.vulnerability.policy import ScanPolicy
from pulse.services.enrichment_pipeline import EnrichmentPipeline
from pulse.config import get_setting

logger = logging.getLogger(__name__)

@dataclass
class VerificationResult:
    findings: List[VulnerabilityFinding]
    total_findings: int
    blocking_findings: int
    verified_safe: bool
    policy_version: str
    provider_summary: Dict[str, Any]
    duration_ms: float
    cache_hit: bool = False
    expires_at: Optional[datetime] = None

class UpgradeVerificationService:
    """Orchestrates on-demand candidate version verification scans using standard enrichment pipeline."""
    
    _cache: Dict[Tuple[str, str, str], VerificationResult] = {}

    @classmethod
    def get_cache_ttl_hours(cls) -> int:
        try:
            return int(get_setting("UPGRADE_VERIFICATION_CACHE_HOURS", "24"))
        except (ValueError, TypeError):
            return 24

    def verify_candidate(self, package_name: str, version: str, ecosystem: str) -> VerificationResult:
        cache_key = (ecosystem.lower(), package_name.lower(), version.strip())
        now = datetime.now()

        if cache_key in self._cache:
            res = self._cache[cache_key]
            if res.expires_at and res.expires_at > now:
                res.cache_hit = True
                return res

        start_time = time.time()
        pkg = PackageInfo(name=package_name, version=version, ecosystem=ecosystem)
        pipeline = EnrichmentPipeline()
        enrichment = pipeline.run([pkg], progress=None)

        findings = enrichment.findings
        blocking_findings = [f for f in findings if ScanPolicy.is_blocking(f)]

        ttl = self.get_cache_ttl_hours()
        result = VerificationResult(
            findings=findings,
            total_findings=len(findings),
            blocking_findings=len(blocking_findings),
            verified_safe=len(blocking_findings) == 0,
            policy_version=ScanPolicy.POLICY_VERSION,
            provider_summary={
                "osv": True,
                "nvd": True,
                "kev": True,
                "epss": True
            },
            duration_ms=round((time.time() - start_time) * 1000, 2),
            cache_hit=False,
            expires_at=now + timedelta(hours=ttl)
        )

        self._cache[cache_key] = result
        return result

    @classmethod
    def clear_cache(cls):
        cls._cache.clear()
