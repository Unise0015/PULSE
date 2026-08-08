import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from pulse.ecosystems.smart_detection import (
    SmartEcosystemDetector, DetectionResult, DetectionStatus, ResolutionScore, RegistryValidationResult
)
from pulse.ecosystems.base import EcosystemRegistry, EcosystemPlugin, PluginManifest

def _make_mock_registry():
    registry = EcosystemRegistry()
    providers = {}
    
    mapping = {
        "Python": ("PyPI", "python-pypi"),
        "Node.js": ("npm", "nodejs-npm"),
        "Rust": ("crates.io", "rust-crates"),
        "Ruby": ("RubyGems", "ruby-gems"),
        "Composer": ("Packagist", "php-packagist"),
        "Go": ("Go Modules", "go-modules"),
        "NuGet": ("NuGet", "dotnet-nuget"),
        "Maven": ("Maven Central", "java-maven"),
    }
    
    for display_name, (reg_name, manifest_id) in mapping.items():
        provider = MagicMock(spec=EcosystemPlugin)
        provider.display_name = display_name
        provider.registry_name = reg_name
        provider.manifest = PluginManifest(
            id=manifest_id,
            name=display_name,
            ecosystem=reg_name,
        )
        registry.register(provider)
        providers[display_name] = provider
        
    return registry, providers

class TestAutoDetection:
    def test_flask_resolves_to_pypi(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        res_scores = [ResolutionScore(ecosystem="Python", score=110, validation=val)]
        with patch.object(detector, 'detect', return_value=(res_scores, DetectionStatus.SUCCESS)):
            result = detector.resolve_package("flask", tmp_path)

        assert result.status == DetectionStatus.SUCCESS
        assert result.provider.display_name == "Python"
        assert result.registry_name == "PyPI"

    def test_django_resolves_to_pypi(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        res_scores = [ResolutionScore(ecosystem="Python", score=110, validation=val)]
        with patch.object(detector, 'detect', return_value=(res_scores, DetectionStatus.SUCCESS)):
            result = detector.resolve_package("Django", tmp_path, version="3.2")

        assert result.status == DetectionStatus.SUCCESS
        assert result.provider.display_name == "Python"
        assert result.registry_name == "PyPI"

    def test_react_resolves_to_npm(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        res_scores = [ResolutionScore(ecosystem="Node.js", score=110, validation=val)]
        with patch.object(detector, 'detect', return_value=(res_scores, DetectionStatus.SUCCESS)):
            result = detector.resolve_package("react", tmp_path)

        assert result.status == DetectionStatus.SUCCESS
        assert result.provider.display_name == "Node.js"
        assert result.registry_name == "npm"

    def test_serde_resolves_to_crates(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        res_scores = [ResolutionScore(ecosystem="Rust", score=110, validation=val)]
        with patch.object(detector, 'detect', return_value=(res_scores, DetectionStatus.SUCCESS)):
            result = detector.resolve_package("serde", tmp_path)

        assert result.status == DetectionStatus.SUCCESS
        assert result.provider.display_name == "Rust"
        assert result.registry_name == "crates.io"

    def test_rails_resolves_to_rubygems(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        res_scores = [ResolutionScore(ecosystem="Ruby", score=110, validation=val)]
        with patch.object(detector, 'detect', return_value=(res_scores, DetectionStatus.SUCCESS)):
            result = detector.resolve_package("rails", tmp_path)

        assert result.status == DetectionStatus.SUCCESS
        assert result.provider.display_name == "Ruby"
        assert result.registry_name == "RubyGems"

    def test_laravel_resolves_to_packagist(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        res_scores = [ResolutionScore(ecosystem="Composer", score=110, validation=val)]
        with patch.object(detector, 'detect', return_value=(res_scores, DetectionStatus.SUCCESS)):
            result = detector.resolve_package("laravel/framework", tmp_path)

        assert result.status == DetectionStatus.SUCCESS
        assert result.provider.display_name == "Composer"
        assert result.registry_name == "Packagist"


class TestAmbiguousDetection:
    def test_ambiguous_redis_shows_selection(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        val = RegistryValidationResult(package_exists=True, version_exists=True, latest_available_version=None, network_error=False, http_status=200)
        candidates = [
            ResolutionScore(ecosystem="Python", score=10, validation=val),
            ResolutionScore(ecosystem="Node.js", score=10, validation=val),
            ResolutionScore(ecosystem="Ruby", score=10, validation=val),
        ]
        with patch.object(detector, 'detect', return_value=(candidates, DetectionStatus.AMBIGUOUS)):
            result = detector.resolve_package("redis", tmp_path)

        assert result.status == DetectionStatus.AMBIGUOUS
        assert len(result.candidates) >= 2

    def test_no_candidates_shows_full_list(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        with patch.object(detector, 'detect', return_value=([], DetectionStatus.PACKAGE_NOT_FOUND)):
            result = detector.resolve_package("nonexistent-pkg-xyz", tmp_path)

        assert result.status == DetectionStatus.PACKAGE_NOT_FOUND


class TestDetectionErrorRecovery:
    def test_detection_exception_returns_user_selection(self, tmp_path):
        registry, providers = _make_mock_registry()
        detector = SmartEcosystemDetector(registry)

        with patch.object(detector, 'detect', side_effect=RuntimeError("Network error")):
            result = detector.resolve_package("flask", tmp_path)

        assert result.status == DetectionStatus.NETWORK_ERROR
