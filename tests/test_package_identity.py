import pytest

from pulse.ecosystems.package_identity import get_canonical_package_info, resolve_technology_package
from pulse.website.signatures.angular import AngularSignature, AngularJSSignature
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer
from pulse.website.capability import evaluate_correlation_eligibility
from pulse.domain.models import TechnologyFingerprint


@pytest.mark.parametrize("alias,expected", [
    ("angular.js", "angular"), ("angularjs", "angular"), ("@angular/core", "@angular/core"),
    ("vue.js", "vue"), ("spring", "org.springframework:spring-core"),
    ("nextjs", "next"), ("tailwind", "tailwindcss")])
def test_aliases_agree_across_resolver_entry_points(alias, expected):
    assert get_canonical_package_info(alias)[0] == expected
    assert resolve_technology_package(alias, "1.2.3").name == expected


def test_angularjs_and_modern_angular_remain_distinct():
    modern = AngularSignature()
    legacy = AngularJSSignature()
    assert modern.match({}, '<app ng-version="17.0.0">', {}, [])
    assert not modern.match({}, '<div ng-app="example">', {}, ["angular-1.8.2.min.js"])
    assert legacy.match({}, '<div ng-app="example">', {}, ["angular-1.8.2.min.js"])
    assert legacy.extract_version({}, "", {}, ["angular-1.8.2.min.js"]) == "1.8.2"
    technologies = [TechnologyFingerprint(name=name, version=version, category="Framework", confidence=100)
                    for name, version in [("Angular", "17.0.0"), ("AngularJS", "1.8.2")]]
    assert len(WebsiteFingerprintAnalyzer()._deduplicate(technologies)) == 2
    assert evaluate_correlation_eligibility(technologies[0]).package_name == "@angular/core"
    assert evaluate_correlation_eligibility(technologies[1]).package_name == "angular"
    # Literal package names keep their registry meaning.
    assert get_canonical_package_info("angular")[0] == "angular"
