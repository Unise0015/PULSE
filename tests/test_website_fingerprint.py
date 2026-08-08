import pytest
import httpx
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.domain.models import TechnologyCategory

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

def test_security_headers():
    analyzer = WebsiteFingerprintAnalyzer()
    headers = httpx.Headers({
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "Strict-Transport-Security": "max-age=31536000"
    })
    
    analyzer._assess_security_headers(headers)
    
    csp = next(h for h in analyzer.security_headers if h.header_name == "Content-Security-Policy")
    assert csp.status == "Weak"
    assert "unsafe-inline" in csp.details
    
    hsts = next(h for h in analyzer.security_headers if h.header_name == "Strict-Transport-Security")
    assert hsts.status == "Present"
    
    xframe = next(h for h in analyzer.security_headers if h.header_name == "X-Frame-Options")
    assert xframe.status == "Missing"
    assert xframe.details == "Header is not set."

def test_deduplication():
    analyzer = WebsiteFingerprintAnalyzer()
    from pulse.domain.models import TechnologyFingerprint
    
    t1 = TechnologyFingerprint(name="jquery", version=None, category=TechnologyCategory.UI_LIBRARY, confidence=60)
    t2 = TechnologyFingerprint(name="jquery", version="3.5.1", category=TechnologyCategory.UI_LIBRARY, confidence=85)
    t3 = TechnologyFingerprint(name="JQuery", version="2.0.0", category=TechnologyCategory.UI_LIBRARY, confidence=70)
    
    deduped = analyzer._deduplicate([t1, t2, t3])
    
    assert len(deduped) == 1
    assert deduped[0].name.lower() == "jquery"
    assert deduped[0].version == "3.5.1"
    assert deduped[0].confidence == 85

def test_scan_flow_full(monkeypatch):
    def mock_stream(self, method, url, **kwargs):
        html = '''
        <html>
        <head>
            <meta name="generator" content="WordPress 6.7">
            <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
        </head>
        <body>
            <div id="wp-content/themes/something"></div>
        </body>
        </html>
        '''
        return MockResponse(
            headers={"Server": "nginx/1.24.0"},
            content=html
        )
        
    monkeypatch.setattr(httpx.Client, "stream", mock_stream)
    
    analyzer = WebsiteFingerprintAnalyzer()
    assessment = analyzer.scan("https://example.com")
    
    techs = {t.name.lower(): t for t in assessment.technologies}
    assert "wordpress" in techs
    assert techs["wordpress"].version == "6.7"
    
    assert "jquery" in techs
    assert techs["jquery"].version == "3.5.1"
    
    assert "nginx" in techs
    assert techs["nginx"].version == "1.24.0"
