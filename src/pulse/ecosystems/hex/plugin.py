"""
Elixir / Erlang Hex.pm Ecosystem Provider for PULSE.
Parses mix.exs and mix.lock. Validates against Hex.pm registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class HexPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="hex",
            name="Hex",
            ecosystem="Hex",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="hex",
            display_name="Hex",
            registry_name="Hex.pm",
            package_manager="mix",
            ecosystem_type="application",
            osv_ecosystem="Hex",
            registry_url="https://hex.pm"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "mix.exs").exists() or (root / "mix.lock").exists() or (root / "rebar.config").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        lockfile = root / "mix.lock"

        if lockfile.exists():
            try:
                content = lockfile.read_text(encoding="utf-8")
                import re
                matches = re.findall(r'"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"', content)
                for name, ver in matches:
                    deps.append(RawDependency(
                        name=name,
                        version_spec=ver,
                        ecosystem="Hex",
                        source_file=lockfile.name
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
                ecosystem="Hex",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://hex.pm/api/packages/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("releases", [{}])[0].get("version") if isinstance(data, dict) else None
                has_version = True
                if version:
                    versions = [r.get("version") for r in data.get("releases", [])]
                    has_version = version in versions
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
