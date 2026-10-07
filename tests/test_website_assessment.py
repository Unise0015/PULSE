import httpx
import pytest

from pulse.state import AppState
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.website.acquisition import fetch_observation


@pytest.fixture
def synthetic_http(monkeypatch):
    real_client = httpx.Client
    def install(handler):
        def client(**kwargs):
            transport = kwargs.pop("transport", None)
            if transport:
                transport.close()
            return real_client(transport=httpx.MockTransport(handler), **kwargs)
        monkeypatch.setattr(httpx, "Client", client)
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


def test_redirect_uses_final_host_for_auxiliary_observations(synthetic_http):
    observed = []
    def respond(request):
        observed.append(str(request.url))
        if request.url.host == "start.invalid":
            return httpx.Response(302, headers={"Location": "https://final.invalid/page"})
        if request.url.path == "/page":
            return httpx.Response(200, text="<html></html>")
        return httpx.Response(404)
    synthetic_http(respond)
    assessment = WebsiteFingerprintAnalyzer().scan("https://start.invalid")
    assert assessment.url == "https://final.invalid/page"
    assert "https://final.invalid/favicon.ico" in observed
    assert all("start.invalid" not in url for url in observed[1:])


def test_root_limit_marks_assessment_partial(synthetic_http, monkeypatch):
    monkeypatch.setattr("pulse.website.website_fingerprint.MAX_BODY_SIZE", 40)
    synthetic_http(lambda request: httpx.Response(200, text="x" * 100))
    assessment = WebsiteFingerprintAnalyzer().scan("https://fixture.invalid")
    assert assessment.status == "PARTIAL"
    assert any("download limit" in warning for warning in assessment.warnings)


def test_broken_signature_registry_still_returns_diagnostics(synthetic_http, monkeypatch):
    synthetic_http(lambda request: httpx.Response(200, text="<html></html>"))
    def fail_load():
        raise ValueError("fixture invalid signature")
    monkeypatch.setattr("pulse.website.website_fingerprint.SignatureRegistry.load", fail_load)
    assessment = WebsiteFingerprintAnalyzer().scan("https://fixture.invalid")
    assert assessment.status == "PARTIAL"
    assert assessment.security_headers
    assert any("signatures could not be loaded" in warning for warning in assessment.warnings)


@pytest.mark.parametrize("header,value,expected", [
    ("X-Content-Type-Options", "disabled", "Misconfigured"),
    ("X-Content-Type-Options", "nosniff", "Present"),
    ("X-Frame-Options", "ALLOW-FROM https://example.com", "Misconfigured"),
    ("X-Frame-Options", "SAMEORIGIN", "Present"),
    ("Strict-Transport-Security", "max-age=0", "Weak"),
    ("Strict-Transport-Security", "max-age=invalid", "Weak"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains", "Present"),
])
def test_security_header_values_are_checked(header, value, expected):
    analyzer = WebsiteFingerprintAnalyzer()
    analyzer._assess_security_headers({header: value})
    result = next(h for h in analyzer.security_headers if h.header_name == header)
    assert result.status == expected
    missing = next(h for h in analyzer.security_headers if h.status == "Missing")
    assert missing.details != "Header is not set."


@pytest.mark.parametrize("blocked", ["http://127.0.0.1/private", "http://10.0.0.1/private", "http://[::1]/private"])
def test_external_only_blocks_redirect_before_request(synthetic_http, monkeypatch, blocked):
    observed = []
    def respond(request):
        observed.append(str(request.url))
        return httpx.Response(302, headers={"Location": blocked})
    synthetic_http(respond)
    monkeypatch.setattr("pulse.website.website_fingerprint.get_setting", lambda key, default="": "true" if key == "EXTERNAL_ONLY" else default)
    assessment = WebsiteFingerprintAnalyzer().scan("https://public.invalid")
    assert assessment.status == "INVALID"
    assert any("External-only policy" in warning for warning in assessment.warnings)
    assert observed == ["https://public.invalid"]


def test_auxiliary_redirects_obey_external_only_policy(synthetic_http, monkeypatch):
    observed = []
    def respond(request):
        observed.append(str(request.url))
        if request.url.path in ("/favicon.ico", "/robots.txt"):
            return httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})
        return httpx.Response(200, text="<html></html>")
    synthetic_http(respond)
    monkeypatch.setattr("pulse.website.website_fingerprint.get_setting", lambda key, default="": "true" if key == "EXTERNAL_ONLY" else default)
    assessment = WebsiteFingerprintAnalyzer().scan("https://public.invalid")
    assert all("127.0.0.1" not in url for url in observed)
    assert assessment.status == "PARTIAL"
    assert any("External-only policy" in warning for warning in assessment.warnings)


def test_redirect_loop_stops_at_limit(synthetic_http):
    observed = []
    def respond(request):
        observed.append(str(request.url))
        return httpx.Response(302, headers={"Location": "/loop"})
    synthetic_http(respond)
    assessment = WebsiteFingerprintAnalyzer().scan("https://public.invalid")
    assert assessment.status == "ERROR"
    assert len(observed) == 6
    assert any("redirect limit" in warning for warning in assessment.warnings)


def test_cross_origin_redirect_does_not_forward_authorization(synthetic_http):
    observed = []
    def respond(request):
        observed.append(request)
        if request.url.host == "start.invalid":
            return httpx.Response(302, headers={"Location": "https://final.invalid/"})
        return httpx.Response(200, text="complete")
    synthetic_http(respond)
    response = fetch_observation("https://start.invalid/", timeout=1, max_bytes=100,
                                 headers={"Authorization": "Bearer synthetic-fixture"})
    assert response.text == "complete"
    assert observed[0].headers["Authorization"] == "Bearer synthetic-fixture"
    assert "Authorization" not in observed[1].headers


def test_disabled_redirects_return_original_response(synthetic_http):
    observed = []
    def respond(request):
        observed.append(request)
        return httpx.Response(302, headers={"Location": "/next"})
    synthetic_http(respond)
    response = fetch_observation("https://fixture.invalid", timeout=1, max_bytes=100, follow_redirects=False)
    assert response.status_code == 302
    assert len(observed) == 1


@pytest.mark.parametrize("encoding,raw_deflate", [("gzip", False), ("deflate", False), ("deflate", True)])
def test_compressed_response_is_limited_inside_decompression(synthetic_http, monkeypatch, encoding, raw_deflate):
    import zlib
    payload = b"x" * 1000000
    wbits = 16 + zlib.MAX_WBITS if encoding == "gzip" else -zlib.MAX_WBITS if raw_deflate else zlib.MAX_WBITS
    compressor = zlib.compressobj(wbits=wbits)
    encoded = compressor.compress(payload) + compressor.flush()
    real_decoder = zlib.decompressobj
    output_sizes = []
    class TrackedDecoder:
        def __init__(self, *args):
            self.decoder = real_decoder(*args)
        def decompress(self, data, max_length=0):
            assert max_length > 0, "Decompression must have an allocation limit"
            result = self.decoder.decompress(data, max_length)
            output_sizes.append(len(result))
            return result
        def __getattr__(self, name):
            return getattr(self.decoder, name)
    monkeypatch.setattr("pulse.website.acquisition.zlib.decompressobj", TrackedDecoder)
    synthetic_http(lambda request: httpx.Response(200, headers={"Content-Encoding": encoding}, stream=httpx.ByteStream(encoded)))
    response = fetch_observation("https://fixture.invalid", timeout=1, max_bytes=1000)
    assert response.content == b"x" * 1000
    assert response.extensions["pulse_body_limit_reached"]
    assert max(output_sizes) <= 1000


def test_nested_compressed_response_decodes_when_below_limit(synthetic_http):
    import gzip
    import zlib
    payload = b"<html>complete</html>"
    encoded = zlib.compress(gzip.compress(payload))
    synthetic_http(lambda request: httpx.Response(200, headers={"Content-Encoding": "gzip, deflate"}, stream=httpx.ByteStream(encoded)))
    response = fetch_observation("https://fixture.invalid", timeout=1, max_bytes=1000)
    assert response.content == payload
    assert not response.extensions["pulse_body_limit_reached"]


@pytest.mark.parametrize("target", ["http://app.localhost", "http://APP.LOCALHOST./", "http://localhost./"])
def test_external_only_rejects_localhost_subdomains(target):
    from pulse.website.acquisition import validate_url
    assert validate_url(target, external_only=True)[0] is False


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "::1", "169.254.169.254", "100.64.0.1"])
def test_external_only_rejects_private_dns_answers(monkeypatch, address):
    import socket
    from pulse.website.acquisition import _PublicNetworkBackend, WebsiteURLPolicyError
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))])
    with pytest.raises(WebsiteURLPolicyError):
        _PublicNetworkBackend().connect_tcp("public-name.invalid", 443, timeout=1)


def test_external_only_connects_to_checked_ip_and_preserves_tls_origin(monkeypatch):
    import socket
    import httpcore
    connected = []
    tls_names = []
    writes = []
    class Stream(httpcore.NetworkStream):
        def read(self, max_bytes, timeout=None):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        def write(self, buffer, timeout=None):
            writes.append(buffer)
        def close(self):
            pass
        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            tls_names.append(server_hostname)
            return self
        def get_extra_info(self, info):
            return None
    def connect(self, host, port, **kwargs):
        connected.append((host, port))
        return Stream()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    response = fetch_observation("https://public-name.invalid", timeout=1, max_bytes=100, external_only=True)
    assert response.content == b"ok"
    assert connected == [("93.184.216.34", 443)]
    assert tls_names == ["public-name.invalid"]
    assert b"Host: public-name.invalid" in b"".join(writes)


@pytest.mark.parametrize("size,limited", [(4, False), (5, True)])
def test_buffered_response_at_limit_is_complete(synthetic_http, size, limited):
    synthetic_http(lambda request: httpx.Response(200, content=b"x" * size))
    response = fetch_observation("https://fixture.invalid", timeout=1, max_bytes=4)
    assert response.content == b"xxxx"
    assert response.extensions["pulse_body_limit_reached"] is limited
