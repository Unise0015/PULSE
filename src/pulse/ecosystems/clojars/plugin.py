"""
Clojure Clojars Ecosystem Provider for PULSE.
Parses project.clj and deps.edn. Validates against Clojars registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class ClojarsPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="clojars",
            name="Clojars",
            ecosystem="Clojars",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="clojars",
            display_name="Clojars",
            registry_name="Clojars",
            package_manager="lein",
            ecosystem_type="application",
            osv_ecosystem="Clojars",
            registry_url="https://clojars.org"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "project.clj").exists() or (root / "deps.edn").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        proj = root / "project.clj"

        if proj.exists():
            try:
                content = proj.read_text(encoding="utf-8")
                import re
                matches = re.findall(r'\[([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)\s+"([^"]+)"\]', content)
                for name, ver in matches:
                    deps.append(RawDependency(
                        name=name,
                        version_spec=ver,
                        ecosystem="Clojars",
                        source_file=proj.name
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
                ecosystem="Clojars",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://clojars.org/api/artifacts/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("latest_release") or data.get("latest_version")
                has_version = True
                if version:
                    has_version = any(v.get("version") == version for v in data.get("recent_versions", []))
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
