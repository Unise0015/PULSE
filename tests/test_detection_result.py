import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from pulse.ecosystems.smart_detection import (
    SmartEcosystemDetector, DetectionResult, DetectionSource, ResolutionScore
)
from pulse.ecosystems.base import EcosystemRegistry, ECOSYSTEM_REGISTRY_MAP


class TestDetectionResult:
    def test_detection_result_defaults(self):
        result = DetectionResult()
        assert result.provider is None
        assert result.registry_name is None
        assert result.confidence == 0
        assert result.detection_source == DetectionSource.REGISTRY_LOOKUP
        assert result.candidates == []

    def test_detection_result_with_provider(self):
        mock_provider = MagicMock()
        mock_provider.display_name = "Python"
        mock_provider.registry_name = "PyPI"

        result = DetectionResult(
            provider=mock_provider,
            registry_name="PyPI",
            confidence=100,
            detection_source=DetectionSource.REGISTRY_LOOKUP,
            candidates=[mock_provider]
        )
        assert result.provider is mock_provider
        assert result.registry_name == "PyPI"
        assert result.confidence == 100

    def test_detection_source_values(self):
        assert DetectionSource.LOCAL_LOCKFILE.value == "Local Lockfile"
        assert DetectionSource.NAMING_HEURISTIC.value == "Naming Heuristic"
        assert DetectionSource.REGISTRY_LOOKUP.value == "Registry Lookup"
        assert DetectionSource.CACHE.value == "Cache"
        assert DetectionSource.USER_SELECTION.value == "User Selection"

    def test_ambiguous_detection_result(self):
        p1 = MagicMock()
        p1.display_name = "Python"
        p1.registry_name = "PyPI"
        p2 = MagicMock()
        p2.display_name = "Node.js"
        p2.registry_name = "npm"

        result = DetectionResult(
            registry_name="PyPI",
            confidence=10,
            candidates=[p1, p2]
        )
        assert result.provider is None
        assert len(result.candidates) == 2

    def test_resolution_score_confidence_property(self):
        score = ResolutionScore(ecosystem="Python", score=95)
        assert score.confidence == 95

class TestEcosystemRegistryMap:
    def test_all_ecosystems_mapped(self):
        expected = {
            "Python": "PyPI",
            "Node.js": "npm",
            "Rust": "crates.io",
            "Go": "Go Modules",
            "Ruby": "RubyGems",
            "Composer": "Packagist",
            "NuGet": "NuGet",
            "Maven": "Maven Central",
        }
        for eco, reg in expected.items():
            assert ECOSYSTEM_REGISTRY_MAP.get(eco) == reg, f"Missing or wrong mapping for {eco}"
