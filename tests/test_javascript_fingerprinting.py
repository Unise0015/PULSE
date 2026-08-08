import pytest
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.domain.models import DetectionStatus, ConfidenceBand, DetectionMethod

def test_nextjs_detection():
    analyzer = WebsiteFingerprintAnalyzer()
    
    # HTML with NEXT_DATA
    html_content = '<html><body><div id="__NEXT_DATA__">{"props": {}}</div></body></html>'
    headers = {"X-Nextjs-Cache": "HIT"}
    
    # Mock network call by calling scanner logic or patch httpx
    # To test scanner logic cleanly, we can inject these into analyzer's helper scan routines
    # We can mock httpx.Client stream get to return this response
    # Or test the signatures directly! Let's do both or mock response.
    # Let's mock response content
    pass

class MockResponse:
    def __init__(self, headers, content, cookies=None):
        self.headers = headers
        self.content = content.encode('utf-8')
        self.cookies = cookies or {}

    def iter_bytes(self, chunk_size=8192):
        yield self.content

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def test_nextjs_signature_directly(monkeypatch):
    import httpx
    
    def mock_stream(self, method, url, **kwargs):
        return MockResponse(
            headers={"X-Powered-By": "Next.js/13.4.12", "X-Nextjs-Cache": "HIT"},
            content='<html><body><div id="__NEXT_DATA__"></div></body></html>'
        )
        
    monkeypatch.setattr(httpx.Client, "stream", mock_stream)
    
    analyzer = WebsiteFingerprintAnalyzer()
    assessment = analyzer.scan("https://example.com")
    
    # Verify Next.js is detected
    nextjs = next((t for t in assessment.technologies if t.name == "Next.js"), None)
    assert nextjs is not None
    assert nextjs.version == "13.4.12"
    assert nextjs.version_status == DetectionStatus.VERIFIED
    assert nextjs.confidence >= 95
    assert nextjs.confidence_band == ConfidenceBand.VERIFIED
    assert len(nextjs.cpe_candidates) > 0
    assert nextjs.cpe_candidates[0].cpe == "cpe:2.3:a:vercel:next.js:13.4.12:*:*:*:*:*:*:*"


def test_react_detection_requires_two_matches(monkeypatch):
    import httpx
    
    # Case A: Only 1 match (should NOT match React, minimum matches is 2)
    def mock_stream_one_match(self, method, url, **kwargs):
        return MockResponse(
            headers={},
            content='<html><body><div id="__REACT_DEVTOOLS_GLOBAL_HOOK__"></div></body></html>'
        )
    monkeypatch.setattr(httpx.Client, "stream", mock_stream_one_match)
    
    analyzer = WebsiteFingerprintAnalyzer()
    assessment1 = analyzer.scan("https://example.com")
    react1 = next((t for t in assessment1.technologies if t.name == "React"), None)
    assert react1 is None
    
    # Case B: 2 matches (should detect React)
    def mock_stream_two_matches(self, method, url, **kwargs):
        return MockResponse(
            headers={},
            content='<html><body><div id="react-root" data-reactroot=""></div><script src="react.production.min.js"></script></body></html>'
        )
    monkeypatch.setattr(httpx.Client, "stream", mock_stream_two_matches)
    
    assessment2 = analyzer.scan("https://example.com")
    react2 = next((t for t in assessment2.technologies if t.name == "React"), None)
    assert react2 is not None
    assert react2.confidence_band in (ConfidenceBand.VERIFIED, ConfidenceBand.HIGH, ConfidenceBand.MEDIUM)


def test_angular_version_extraction(monkeypatch):
    import httpx
    
    def mock_stream(self, method, url, **kwargs):
        return MockResponse(
            headers={},
            content='<html><body><div ng-version="15.2.0"></div></body></html>'
        )
    monkeypatch.setattr(httpx.Client, "stream", mock_stream)
    
    analyzer = WebsiteFingerprintAnalyzer()
    assessment = analyzer.scan("https://example.com")
    angular = next((t for t in assessment.technologies if t.name == "Angular"), None)
    assert angular is not None
    assert angular.version == "15.2.0"
    assert angular.version_status == DetectionStatus.VERIFIED
    assert angular.version_confidence == 90 # META/attribute rules


def test_runtime_unknown_version_rule(monkeypatch):
    import httpx
    
    # PHP session cookie found, but no explicit version in header/html
    def mock_stream(self, method, url, **kwargs):
        resp = MockResponse(
            headers={},
            content='<html><body></body></html>'
        )
        resp.cookies = {"PHPSESSID": "abcdef"}
        return resp
        
    monkeypatch.setattr(httpx.Client, "stream", mock_stream)
    
    analyzer = WebsiteFingerprintAnalyzer()
    assessment = analyzer.scan("https://example.com")
    php = next((t for t in assessment.technologies if t.name == "php"), None)
    assert php is not None
    assert php.version is None
    assert php.version_status == DetectionStatus.UNKNOWN


def test_cloudflare_cdn_detection(monkeypatch):
    import httpx
    
    def mock_stream(self, method, url, **kwargs):
        return MockResponse(
            headers={"Server": "cloudflare", "cf-ray": "123456abc"},
            content='<html><body></body></html>'
        )
    monkeypatch.setattr(httpx.Client, "stream", mock_stream)
    
    analyzer = WebsiteFingerprintAnalyzer()
    assessment = analyzer.scan("https://example.com")
    cf = next((t for t in assessment.technologies if t.name == "cloudflare"), None)
    assert cf is not None
    assert cf.category == "CDN"
