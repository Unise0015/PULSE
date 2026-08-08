import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from pulse.remediation.verification_service import UpgradeVerificationService, VerificationResult
from pulse.config import set_setting

def test_verification_cache_expiry():
    UpgradeVerificationService.clear_cache()
    set_setting("UPGRADE_VERIFICATION_CACHE_HOURS", "24")

    service = UpgradeVerificationService()
    mock_pipeline_res = MagicMock(findings=[])

    with patch("pulse.remediation.verification_service.EnrichmentPipeline") as mock_pipeline_cls:
        mock_pipeline_cls.return_value.run.return_value = mock_pipeline_res

        # Initial call -> Cache miss
        res1 = service.verify_candidate("Django", "5.1.15", "PyPI")
        assert not res1.cache_hit
        assert mock_pipeline_cls.return_value.run.call_count == 1

        # Second call -> Cache hit
        res2 = service.verify_candidate("Django", "5.1.15", "PyPI")
        assert res2.cache_hit
        assert mock_pipeline_cls.return_value.run.call_count == 1

        # Expire cache artificially
        key = ("pypi", "django", "5.1.15")
        UpgradeVerificationService._cache[key].expires_at = datetime.now() - timedelta(minutes=1)

        # Third call -> Cache expired, fresh scan
        res3 = service.verify_candidate("Django", "5.1.15", "PyPI")
        assert not res3.cache_hit
        assert mock_pipeline_cls.return_value.run.call_count == 2
