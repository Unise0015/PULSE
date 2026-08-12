import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from pulse.ecosystems.package_resolution import PackageResolutionService, PackageCandidate
from pulse.ecosystems.smart_detection import RegistryValidationResult
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
        # Default: package not found
        return None


NOT_FOUND = RegistryValidationResult(False, False, None, False, 404)
FOUND_WITH_VERSION = lambda v: RegistryValidationResult(True, True, v, False, 200)
FOUND_NO_VERSION = RegistryValidationResult(True, False, None, False, 200)


@pytest.fixture
def mock_providers():
    return [
        DummyProvider("Node.js", "npm"),
        DummyProvider("NuGet", "NuGet"),
        DummyProvider("Python", "PyPI")
    ]


def _patch_native_checks(resolver, npm_result=NOT_FOUND, nuget_result=NOT_FOUND, pypi_result=NOT_FOUND):
    """Patch the real registry check methods to return controlled results."""
    async def mock_npm(client, name, version=None):
        return npm_result
    async def mock_nuget(client, name, version=None):
        return nuget_result
    async def mock_pypi(client, name, version=None):
        return pypi_result
    
    resolver._check_npm = mock_npm
    resolver._check_nuget = mock_nuget
    resolver._check_pypi = mock_pypi


def test_bootstrap_regression_consistency(mock_providers):
    """Bootstrap 4.5.2 -> npm, not NuGet, no ecosystem selection, vuln correlation executes."""
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                mock_search.return_value = [
                    {"name": "bootstrap", "registry": {"name": "npmjs.com", "ecosystem": "npm"}}
                ]
                mock_ver.return_value = {"version": "4.5.2"}

                resolver = PackageResolutionService()
                # npm finds bootstrap with version, nuget also finds it (like real life)
                _patch_native_checks(
                    resolver,
                    npm_result=FOUND_WITH_VERSION("5.3.3"),
                    nuget_result=FOUND_WITH_VERSION("5.3.3"),
                    pypi_result=NOT_FOUND
                )
                
                result = asyncio.run(resolver.resolve("Bootstrap", "4.5.2"))
                
                # Must auto-resolve to npm, NOT prompt for ecosystem
                assert result.requires_user_selection is False
                assert result.package_exists is True
                assert result.version_exists is True
                assert result.ecosystem == "Node.js"
                
                # Provider consistency: the resolved provider must be the one used for scanning
                assert result.provider is not None
                assert result.provider.manifest.ecosystem == "npm"
                assert result.provider.manifest.name == "Node.js"


def test_bootstrap_not_nuget(mock_providers):
    """Even when NuGet also has Bootstrap, the local identity hint must pick npm."""
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                # ecosyste.ms is down / returns empty
                mock_search.return_value = []
                mock_ver.return_value = None

                resolver = PackageResolutionService()
                # Both npm and nuget find bootstrap
                _patch_native_checks(
                    resolver,
                    npm_result=FOUND_WITH_VERSION("5.3.3"),
                    nuget_result=FOUND_WITH_VERSION("5.3.3"),
                    pypi_result=NOT_FOUND
                )
                
                result = asyncio.run(resolver.resolve("Bootstrap", "4.5.2"))
                
                # Must still pick npm due to local identity hint
                assert result.requires_user_selection is False
                assert result.ecosystem == "Node.js"
                assert result.provider.manifest.ecosystem == "npm"


def test_missing_version_keeps_ecosystem(mock_providers):
    """Bootstrap 99.99.99 -> identifies npm, reports version not found, no ecosystem menu."""
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                mock_search.return_value = [
                    {"name": "bootstrap", "registry": {"name": "npmjs.com", "ecosystem": "npm"}}
                ]
                mock_ver.return_value = None  # Version doesn't exist on ecosyste.ms

                resolver = PackageResolutionService()
                # npm finds bootstrap but version is wrong
                _patch_native_checks(
                    resolver,
                    npm_result=RegistryValidationResult(True, False, "5.3.3", False, 200),
                    nuget_result=NOT_FOUND,
                    pypi_result=NOT_FOUND
                )
                
                result = asyncio.run(resolver.resolve("Bootstrap", "99.99.99"))
                
                # Must NOT prompt for ecosystem — ecosystem is locked
                assert result.requires_user_selection is False
                assert result.package_exists is True
                assert result.version_exists is False
                assert result.ecosystem == "Node.js"


def test_ambiguous_package_prompts_user(mock_providers):
    """A package found equally in npm and PyPI with no local identity hint -> ambiguous."""
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                mock_search.return_value = [
                    {"name": "testpkg", "registry": {"name": "npmjs.com", "ecosystem": "npm"}},
                    {"name": "testpkg", "registry": {"name": "pypi.org", "ecosystem": "pypi"}},
                ]
                mock_ver.return_value = {"version": "1.0.0"}

                resolver = PackageResolutionService()
                # nuget doesn't find it
                _patch_native_checks(
                    resolver,
                    npm_result=NOT_FOUND,  # Already found by ecosyste.ms
                    nuget_result=NOT_FOUND,
                    pypi_result=NOT_FOUND   # Already found by ecosyste.ms
                )
                
                result = asyncio.run(resolver.resolve("testpkg", "1.0.0"))
                
                # Should require user selection — npm and pypi are equal confidence
                assert result.requires_user_selection is True
                assert len(result.alternative_candidates) >= 2


def test_unknown_package_not_found(mock_providers):
    """A package not found anywhere -> not found."""
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                mock_search.return_value = []
                mock_ver.return_value = None

                resolver = PackageResolutionService()
                _patch_native_checks(resolver)
                
                result = asyncio.run(resolver.resolve("UnknownPackage", "1.0.0"))
                
                assert len(result.candidates) == 0
                assert result.requires_user_selection is False
                assert result.provider is None


def test_provider_consistency(mock_providers):
    """The resolved provider must be the exact same object used for scanning."""
    with patch('pulse.ecosystems.registry.PluginRegistry.load', return_value=mock_providers):
        with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.search_packages') as mock_search:
            with patch('pulse.ecosystems.ecosystems_client.EcosystemsClient.get_package_version') as mock_ver:
                mock_search.return_value = [
                    {"name": "django", "registry": {"name": "pypi.org", "ecosystem": "pypi"}}
                ]
                mock_ver.return_value = {"version": "3.2"}

                resolver = PackageResolutionService()
                _patch_native_checks(
                    resolver,
                    npm_result=NOT_FOUND,
                    nuget_result=NOT_FOUND,
                    pypi_result=NOT_FOUND  # Already found by ecosyste.ms
                )
                
                result = asyncio.run(resolver.resolve("django", "3.2"))
                
                assert result.provider is not None
                # The provider used for scanning must match the ecosystem
                assert result.provider.manifest.name == result.ecosystem
                assert result.provider.manifest.name == "Python"
                # It must be one of the original provider objects
                assert result.provider in mock_providers
