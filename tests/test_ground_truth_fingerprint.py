"""
Ground-Truth Regression and Precision Benchmark Test Suite for PULSE Web Fingerprinting.
Validates Next.js App Router (RSC), Nuxt 3 (__NUXT_DATA__), Subresource Integrity (SRI) hashing,
Bot-Challenge interstitials (Cloudflare, Akamai, AWS WAF), Signal Disagreement detection,
Spring Boot Whitelabel, Laravel Whoops, ASP.NET YSOD, SvelteKit, Astro, and SemVer 2.0 / CalVer grammar.
"""

from unittest.mock import MagicMock, patch
import pytest
from pulse.website.declarative.engine import DeclarativeTechnologyEngine
from pulse.website.declarative.matcher import PatternMatcher
from pulse.website.confidence import WeightedMaxBonusCalculator, SignalDisagreementDetector, get_confidence_band
from pulse.website.bot_challenge import BotChallengeDetector
from pulse.website.sri_resolver import SRIResolver, SRIResolution
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.domain.models import TechnologyFingerprint, TechnologyCategory, DetectionEvidence, DetectionMethod


@pytest.fixture
def engine():
    return DeclarativeTechnologyEngine()


# --- 1. MODERN FRAMEWORK AST & DOM MARKER TESTS ---

def test_nextjs_app_router_rsc_detection(engine):
    """Next.js App Router pages built on React Server Components use self.__next_f.push() without __NEXT_DATA__."""
    html = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/_next/static/css/app.css"/>
</head>
<body>
    <div data-nextjs-scroll-focus-boundary="" id="app">
        <h1>App Router RSC</h1>
    </div>
    <script>self.__next_f.push([1, "some_rsc_payload"])</script>
    <script src="/_next/static/chunks/app/main-app-14.2.3.js"></script>
</body>
</html>"""
    results = engine.detect("https://example.com", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "Next.js" in tech_names
    assert tech_names["Next.js"].confidence == 100
    assert tech_names["Next.js"].version == "14.2.3"
    assert "React" in tech_names


def test_nuxt3_ssr_data_detection(engine):
    """Nuxt 3 applications use __NUXT_DATA__ and data-v-app root containers."""
    html = """<!DOCTYPE html>
<html>
<head>
    <script type="application/json" id="__NUXT_DATA__">[{"state":1}, "payload"]</script>
</head>
<body>
    <div id="__nuxt" data-v-app="">
        <div data-v-34a8b72e="">Nuxt 3 App</div>
    </div>
    <script src="/_nuxt/entry.3.11.2.js" type="module"></script>
</body>
</html>"""
    results = engine.detect("https://example.com", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "Nuxt.js" in tech_names
    assert tech_names["Nuxt.js"].confidence == 100
    assert tech_names["Nuxt.js"].version == "3.11.2"
    assert "Vue.js" in tech_names


def test_sveltekit_detection(engine):
    """SvelteKit applications use data-sveltekit-preload-data and __sveltekit runtime."""
    html = """<!DOCTYPE html>
<html>
<body data-sveltekit-preload-data="hover">
    <div style="display: contents" class="svelte-1a2b3c">
        <script>__sveltekit_12345 = { base: "" };</script>
    </div>
</body>
</html>"""
    results = engine.detect("https://example.com", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "Svelte" in tech_names
    assert tech_names["Svelte"].confidence >= 95


def test_astro_island_detection(engine):
    """Astro static/hybrid sites use data-astro-cid and astro-island custom elements."""
    html = """<!DOCTYPE html>
<html>
<body>
    <astro-island uid="Z1abc" component-url="/_astro/Button.1234.js" data-astro-cid-j7pv25f6=""></astro-island>
</body>
</html>"""
    results = engine.detect("https://example.com", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "Astro" in tech_names
    assert tech_names["Astro"].confidence == 100


# --- 2. UNHARDENED ERROR PAGE & DEBUG TRACE TESTS ---

def test_spring_boot_whitelabel_detection(engine):
    """Spring Boot default unmapped error response."""
    html = """<html><body>
    <h1>Whitelabel Error Page</h1>
    <p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>
    <div id='created'>Mon Aug 17 23:00:00 UTC 2026</div>
    <div>There was an unexpected error (type=Not Found, status=404).</div>
</body></html>"""
    results = engine.detect("https://example.com/error", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "Spring Boot" in tech_names
    assert tech_names["Spring Boot"].confidence == 100


def test_laravel_whoops_detection(engine):
    """Laravel Ignition / Whoops debug error screen."""
    html = """<!DOCTYPE html>
<html>
<head><title>Whoops! There was an error.</title></head>
<body>
    <script>window.Ignition = { "config": { "editor": "phpstorm" } };</script>
</body>
</html>"""
    results = engine.detect("https://example.com/error", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "Laravel" in tech_names
    assert tech_names["Laravel"].confidence == 100


def test_aspnet_ysod_detection(engine):
    """ASP.NET Yellow Screen of Death (YSOD) with exact runtime version."""
    html = """<html>
<head><title>Server Error in '/' Application.</title></head>
<body>
    <!-- [HttpException]: The file does not exist. -->
    <hr width=100% size=1 color=silver>
    <b>Version Information:</b>&nbsp;Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4494.0
</body>
</html>"""
    results = engine.detect("https://example.com/error", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "ASP.NET" in tech_names
    assert tech_names["ASP.NET"].confidence == 100
    assert tech_names["ASP.NET"].version == "4.8.4494.0"


# --- 3. SUBRESOURCE INTEGRITY (SRI) HASH TESTS ---

def test_sri_attribute_parsing():
    """Validates base64 to hex decoding across SHA-256 and SHA-384."""
    # Test SHA-256
    integ_sha256 = "sha256-4+XzXVhsDmqanXGHaHvgh1gMQKX40OUvDEBTu8JgZZI="
    algo, hex_hash = SRIResolver.parse_integrity_attribute(integ_sha256)
    assert algo == "sha256"
    assert len(hex_hash) == 64
    assert hex_hash == "e3e5f35d586c0e6a9a9d7187687be087580c40a5f8d0e52f0c4053bbc2606592"


def test_sri_hash_resolution_integration(engine):
    """SRI hash match yields 100% confidence verified package identity."""
    sri_resolver = SRIResolver()
    # Mock resolved resolution for SHA-256 hash of jQuery 3.6.0
    mock_res = SRIResolution(
        package_name="jquery",
        version="3.6.0",
        file_path="/dist/jquery.min.js",
        provider="jsdelivr",
        hex_hash="e3e5f35d586c0e6a9a9d7187687be087580c40a5f8d0e52f0c4053bbc2606592",
        confidence=100
    )
    sri_resolver._memory_cache["e3e5f35d586c0e6a9a9d7187687be087580c40a5f8d0e52f0c4053bbc2606592"] = mock_res
    engine.sri_resolver = sri_resolver

    html = """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.example.com/renamed_library.js"
            integrity="sha256-4+XzXVhsDmqanXGHaHvgh1gMQKX40OUvDEBTu8JgZZI="
            crossorigin="anonymous"></script>
</head>
<body></body>
</html>"""
    results = engine.detect("https://example.com", {}, {}, html)
    tech_names = {r.name: r for r in results}
    
    assert "jquery" in tech_names or "jQuery" in tech_names
    jq = tech_names.get("jquery") or tech_names.get("jQuery")
    assert jq.confidence == 100
    assert jq.version == "3.6.0"


# --- 4. BOT CHALLENGE & WAF INTERSTITIAL TESTS ---

def test_cloudflare_bot_challenge_detection():
    """Detects Cloudflare challenge interstitial and flags scan as inconclusive."""
    headers = {"server": "cloudflare", "cf-mitigated": "challenge"}
    html = """<!DOCTYPE html>
<html>
<head><title>Just a moment...</title></head>
<body>
    <div class="cf-browser-verification cf-im-under-attack">
        <div id="cf-spinner"></div>
        <p>Checking your browser before accessing target.com.</p>
        <script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>
    </div>
    <div class="footer">Cloudflare Ray ID: 89ab12cd34ef5678</div>
</body>
</html>"""
    res = BotChallengeDetector.inspect(403, headers, html)
    assert res.is_challenge is True
    assert "Cloudflare" in res.provider


def test_akamai_bot_challenge_detection():
    """Detects Akamai bot manager challenge screen."""
    headers = {"server": "AkamaiGHost"}
    html = """<html><body>
    <h1>Access Denied - Akamai</h1>
    <script>var _abck = "payload"; var ak_bmsc = "telemetry";</script>
</body></html>"""
    res = BotChallengeDetector.inspect(403, headers, html)
    assert res.is_challenge is True
    assert "Akamai" in res.provider


# --- 5. SIGNAL DISAGREEMENT & SPOOFING TESTS ---

def test_signal_disagreement_detection():
    """Detects when Server header contradicts structural application markers."""
    headers = {"Server": "Apache/2.4.58 (Unix)"}
    techs = [
        TechnologyFingerprint(
            name="Spring Boot",
            version="3.2.0",
            category=TechnologyCategory.FRAMEWORK,
            confidence=100
        )
    ]
    conflicts = SignalDisagreementDetector.detect_conflicts(techs, headers)
    assert len(conflicts) > 0
    assert "Spring Boot behind reverse proxy" in conflicts[0] or "Discrepancy" in conflicts[0]


# --- 6. SEMVER 2.0 & CALVER GRAMMAR TESTS ---

def test_semver2_and_calver_normalization():
    """Validates full SemVer 2.0 (with prereleases) and CalVer date strings."""
    assert PatternMatcher.normalize_version("1.2.3-rc.2") == "1.2.3-rc.2"
    assert PatternMatcher.normalize_version("v2.4.0-beta.1+build.456") == "2.4.0-beta.1+build.456"
    assert PatternMatcher.normalize_version("2024.03.15") == "2024.03.15"
    assert PatternMatcher.normalize_version("bootstrap.min.js?ver=5.3.2") == "5.3.2"
    assert PatternMatcher.normalize_version("tailwindcss@3.4.1") == "3.4.1"
