import pytest
import httpx
from unittest.mock import patch, MagicMock
from pulse.vulnerability.nvd_provider import NVDProvider
from pulse.vulnerability.osv_provider import OSVProvider
from pulse.domain.models import PackageInfo

def test_nvd_provider_timeout_fallback():
    """Test that NVDProvider gracefully handles a timeout and continues."""
    provider = NVDProvider()
    
    with patch.object(provider.client, 'get', side_effect=httpx.TimeoutException("Timeout")):
        # It should try up to _MAX_RETRIES + 1 times and then return None
        result = provider._fetch_cve("CVE-1234")
        assert result is None
        assert provider._warned_unavailable is True

def test_nvd_provider_missing_key_fallback():
    """Test that NVDProvider handles HTTP 403 gracefully."""
    provider = NVDProvider()
    
    mock_response = MagicMock()
    mock_response.status_code = 403
    
    with patch.object(provider.client, 'get', side_effect=httpx.HTTPStatusError("403 Forbidden", request=MagicMock(), response=mock_response)):
        # It should break out of retry loop on 403
        result = provider._fetch_cve("CVE-1234")
        assert result is None

def test_osv_provider_timeout_fallback():
    """Test that OSVProvider gracefully handles a timeout."""
    provider = OSVProvider()
    
    with patch.object(provider.client, 'post', side_effect=httpx.TimeoutException("Timeout")):
        # It should try up to _MAX_RETRIES + 1 times and then return None
        result = provider._fetch_batch([{"version": "1.0", "package": {"name": "test", "ecosystem": "PyPI"}}])
        assert result is None
