import pytest
import asyncio
from unittest.mock import patch, MagicMock

from pulse.ecosystems.package_resolution import PackageResolutionService, PackageCandidate
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest

class DummyProvider(EcosystemPlugin):
    def __init__(self, name="Node.js", ecosystem="npm"):
        self._manifest = PluginManifest(id=name.lower(), name=name, ecosystem=ecosystem)
        
    @property
    def manifest(self): 
        return self._manifest
        
    def detect(self, context): return False
    def parse(self, context): return []
    def resolve(self, deps, ctx): return []
    def normalize(self, res, ctx): return []
    
    async def validate_registry_async(self, client, name, version=None):
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        # Pretend bootstrap exists in npm
        if name.lower() == "bootstrap" and self._manifest.ecosystem == "npm":
            return RegistryValidationResult(
                package_exists=True,
                version_exists=version == "4.5.2",
                latest_available_version="5.0.0",
                network_error=False,
                http_status=200
            )
        return None

@pytest.fixture
def mock_providers():
    return [
        DummyProvider("Node.js", "npm"),
        DummyProvider("NuGet", "NuGet"),
        DummyProvider("Python", "PyPI")
    ]

def test_bootstrap_regression_consistency(mock_providers):
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                # Mock ecosyste.ms response for bootstrap
                mock_search.return_value = [
                    {"name": "bootstrap", "registry": {"name": "npmjs.com", "ecosystem": "npm"}}
                ]
                mock_ver.return_value = {"version": "4.5.2"}

                resolver = PackageResolutionService()
                
                # Test the prompt's exact case
                result = asyncio.run(resolver.resolve("Bootstrap", "4.5.2"))
                
                # Verify that it doesn't prompt for ecosystem
                assert result.requires_user_selection is False
                assert result.package_exists is True
                assert result.version_exists is True
                assert result.ecosystem == "Node.js"
                
                # Verify provider consistency
                assert result.provider is not None
                assert result.provider.manifest.ecosystem == "npm"
                assert result.provider.manifest.name == "Node.js"

def test_missing_version_prompts_user_without_losing_ecosystem(mock_providers):
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                mock_search.return_value = [
                    {"name": "bootstrap", "registry": {"name": "npmjs.com", "ecosystem": "npm"}}
                ]
                mock_ver.return_value = None  # Version doesn't exist

                resolver = PackageResolutionService()
                
                result = asyncio.run(resolver.resolve("Bootstrap", "99.99.99"))
                
                assert result.requires_user_selection is False
                assert result.package_exists is True
                assert result.version_exists is False
                assert result.ecosystem == "Node.js"

def test_ambiguous_package_prompts_user(mock_providers):
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                # Mock ecosyste.ms response returning multiple valid hits
                mock_search.return_value = [
                    {"name": "testpkg", "registry": {"name": "npmjs.com", "ecosystem": "npm"}},
                    {"name": "testpkg", "registry": {"name": "pypi.org", "ecosystem": "pypi"}},
                ]
                mock_ver.return_value = {"version": "1.0.0"}

                resolver = PackageResolutionService()
                
                # Test package with no local identity and exact matches in multiple
                result = asyncio.run(resolver.resolve("testpkg", "1.0.0"))
                
                # Should require user selection because confidence difference is < 15
                assert result.requires_user_selection is True
                assert len(result.alternative_candidates) == 2
