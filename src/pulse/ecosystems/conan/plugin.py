"""
C / C++ ConanCenter Ecosystem Provider for PULSE.
Parses conanfile.txt and conanfile.py. Validates against ConanCenter registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class ConanPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="conan",
            name="Conan",
            ecosystem="Conan",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="conan",
            display_name="Conan",
            registry_name="ConanCenter",
            package_manager="conan",
            ecosystem_type="application",
            osv_ecosystem="Conan",
            registry_url="https://center.conan.io"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "conanfile.txt").exists() or (root / "conanfile.py").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        txtfile = root / "conanfile.txt"

        if txtfile.exists():
            try:
                content = txtfile.read_text(encoding="utf-8")
                import re
                in_reqs = False
                for line in content.splitlines():
                    line = line.strip()
                    if line == "[requires]":
                        in_reqs = True
                        continue
                    elif line.startswith("["):
                        in_reqs = False
                        continue
                    if in_reqs and "/" in line:
                        parts = line.split("/")
                        deps.append(RawDependency(
                            name=parts[0],
                            version_spec=parts[1],
                            ecosystem="Conan",
                            source_file=txtfile.name
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
                ecosystem="Conan",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://center.conan.io/v1/conans/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                return RegistryValidationResult(True, True, None, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
