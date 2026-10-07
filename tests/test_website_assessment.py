import httpx
import pytest

from pulse.state import AppState
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.website.acquisition import fetch_observation


@pytest.fixture
def synthetic_http(monkeypatch):
    real_client = httpx.Client
    def install(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
            transport=httpx.MockTransport(handler), **kwargs))
    return install


def test_headers_are_case_insensitive_and_repeated_scans_do_not_accumulate(synthetic_http):
    synthetic_http(lambda request: httpx.Response(200, headers={
        "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"}, text="<html></html>"))
    analyzer = WebsiteFingerprintAnalyzer()
    for _ in range(2):
        assessment = analyzer.scan("https://fixture.invalid")
        headers = {h.header_name: h.status for h in assessment.security_headers}
        assert headers["Content-Security-Policy"] == "Present"
        assert headers["X-Frame-Options"] == "Present"
        assert len(assessment.security_headers) == 8
        assert assessment.status_code == 200


@pytest.mark.parametrize("url", ["", "file:///tmp/fixture", "https://", "https://fixture.invalid:abc", "https://fixture.invalid:99999"])
def test_invalid_urls_return_explicit_assessment(url):
    result = WebsiteFingerprintAnalyzer().scan(url)
    assert result.status == "INVALID"
    assert result.warnings
    assert result.status_code == 0


def test_transport_failure_has_no_fabricated_missing_headers(synthetic_http):
    def fail(request):
        raise httpx.ConnectError("fixture", request=request)
    synthetic_http(fail)
    result = WebsiteFingerprintAnalyzer().scan("https://fixture.invalid")
    assert result.status == "ERROR"
    assert result.security_headers == []
    assert result.warnings


def test_offline_website_never_opens_client(monkeypatch):
    monkeypatch.setattr(AppState, "OFFLINE_MODE", True)
    def forbidden(**kwargs):
        raise AssertionError("HTTP client created in offline mode")
    monkeypatch.setattr(httpx, "Client", forbidden)
    assert WebsiteFingerprintAnalyzer().scan("https://fixture.invalid").status == "OFFLINE"


def test_download_limit_stops_stream_and_closes_it(synthetic_http):
    class LargeBody(httpx.SyncByteStream):
        read = 0
        closed = False
        def __iter__(self):
            for _ in range(100):
                self.read += 8192
                yield b"x" * 8192
        def close(self):
            self.closed = True
    body = LargeBody()
    synthetic_http(lambda request: httpx.Response(200, stream=body))
    response = fetch_observation("https://fixture.invalid/robots.txt", timeout=1, max_bytes=20000)
    assert len(response.content) == 20000
    assert body.read == 24576
    assert body.closed


@pytest.mark.parametrize("body,expected,other", [
    ('<div ng-app="example"></div><script src="/angular-1.8.2.min.js"></script>', "AngularJS", "Angular"),
    ('<app-root ng-version="17.0.0"></app-root>', "Angular", "AngularJS"),
])
def test_real_detection_does_not_merge_angular_generations(synthetic_http, body, expected, other):
    synthetic_http(lambda request: httpx.Response(200, text=body) if request.url.path == "/"
                   else httpx.Response(404, text="Not found"))
    assessment = WebsiteFingerprintAnalyzer().scan("https://fixture.invalid/")
    names = {technology.name for technology in assessment.technologies}
    assert expected in names
    assert other not in names


def test_declarative_detection_failure_marks_partial_coverage(synthetic_http, monkeypatch):
    synthetic_http(lambda request: httpx.Response(200, text='<app-root ng-version="17.0.0"></app-root>')
                   if request.url.path == "/" else httpx.Response(404, text="Not found"))
    def fail_engine():
        raise RuntimeError("fixture detection failure")
    monkeypatch.setattr("pulse.website.website_fingerprint.get_declarative_engine", fail_engine)
    assessment = WebsiteFingerprintAnalyzer().scan("https://fixture.invalid/")
    assert assessment.status == "PARTIAL"
    assert "Declarative technology detection failed" in assessment.warnings[0]
    assert any(technology.name == "Angular" for technology in assessment.technologies)
