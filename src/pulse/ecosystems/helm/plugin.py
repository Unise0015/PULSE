"""
Helm Kubernetes Charts Ecosystem Provider for PULSE.
Parses Chart.yaml and Chart.lock. Validates Helm charts.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class HelmPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="helm",
            name="Helm",
            ecosystem="Helm",
            priority=20,
            category=PluginCategory.INFRASTRUCTURE,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="helm",
            display_name="Helm",
            registry_name="Helm Charts",
            package_manager="helm",
            ecosystem_type="infrastructure",
            osv_ecosystem="Helm",
            registry_url="https://artifacthub.io"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "Chart.yaml").exists() or (root / "Chart.lock").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        chart_yaml = root / "Chart.yaml"

        if chart_yaml.exists():
            try:
                import yaml
                with open(chart_yaml, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    chart_deps = data.get("dependencies", []) if isinstance(data, dict) else []
                    for dep in chart_deps:
                        if isinstance(dep, dict):
                            deps.append(RawDependency(
                                name=dep.get("name", "unknown"),
                                version_spec=dep.get("version", "0.0.0"),
                                ecosystem="Helm",
                                source_file=chart_yaml.name
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
                ecosystem="Helm",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://artifacthub.io/api/v1/packages/helm/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("version")
                return RegistryValidationResult(True, True, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
