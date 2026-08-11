"""
Haskell Hackage Ecosystem Provider for PULSE.
Parses *.cabal and cabal.project. Validates against Hackage registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class HackagePlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="hackage",
            name="Hackage",
            ecosystem="Hackage",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="hackage",
            display_name="Hackage",
            registry_name="Hackage",
            package_manager="cabal",
            ecosystem_type="application",
            osv_ecosystem="Hackage",
            registry_url="https://hackage.haskell.org"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "cabal.project").exists() or any(root.glob("*.cabal"))

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        cabal_files = list(root.glob("*.cabal"))

        for cf in cabal_files:
            try:
                content = cf.read_text(encoding="utf-8")
                import re
                matches = re.findall(r'build-depends:\s*([^,\n]+(?:,[^,\n]+)*)', content, re.IGNORECASE)
                for block in matches:
                    for item in block.split(","):
                        parts = item.strip().split()
                        if parts:
                            pkg_name = parts[0]
                            ver = parts[1] if len(parts) > 1 else "0.0.0"
                            deps.append(RawDependency(
                                name=pkg_name,
                                version_spec=ver.strip("==>=<"),
                                ecosystem="Hackage",
                                source_file=cf.name
                            ))
            except Exception:
                pass

        return deps

    def resolve(self, raw_dependencies: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        return [
            ResolvedDependency(
                name=r.name,
                resolved_version=r.version_spec,
                ecosystem=r.ecosystem,
                source_file=r.source_file
            )
            for r in raw_dependencies
        ]

    def normalize(self, resolved_dependencies: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        return [
            PackageInfo(
                name=r.name,
                version=r.resolved_version,
                ecosystem="Hackage",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://hackage.haskell.org/package/{name}.json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = list(data.keys())[0] if isinstance(data, dict) and data else None
                has_version = True
                if version:
                    has_version = version in data
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
