"""
R / CRAN Ecosystem Provider for PULSE.
Parses DESCRIPTION and renv.lock. Validates against CRAN registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class CranPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="cran",
            name="CRAN",
            ecosystem="CRAN",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="cran",
            display_name="CRAN",
            registry_name="CRAN",
            package_manager="R",
            ecosystem_type="application",
            osv_ecosystem="CRAN",
            registry_url="https://cran.r-project.org"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "DESCRIPTION").exists() or (root / "renv.lock").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        renv = root / "renv.lock"

        if renv.exists():
            try:
                import json
                with open(renv, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    packages = data.get("Packages", {}) if isinstance(data, dict) else {}
                    for name, meta in packages.items():
                        if isinstance(meta, dict):
                            ver = meta.get("Version", "0.0.0")
                            deps.append(RawDependency(
                                name=name,
                                version_spec=ver,
                                ecosystem="CRAN",
                                source_file=renv.name
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
                ecosystem="CRAN",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://crandb.r-pkg.org/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("Version")
                has_version = True
                if version:
                    has_version = (version == latest) or (version in data.get("timeline", {}))
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
