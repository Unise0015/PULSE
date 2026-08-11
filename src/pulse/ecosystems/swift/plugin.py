"""
Swift Package Manager Ecosystem Provider for PULSE.
Parses Package.swift and Package.resolved. Validates against Swift Package Index.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class SwiftPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="swift",
            name="Swift",
            ecosystem="SwiftURL",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="swift",
            display_name="Swift",
            registry_name="Swift Package Index",
            package_manager="swift",
            ecosystem_type="application",
            osv_ecosystem="SwiftURL",
            registry_url="https://swiftpackageindex.com"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "Package.swift").exists() or (root / "Package.resolved").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        resolved_file = root / "Package.resolved"
        swift_file = root / "Package.swift"

        if resolved_file.exists():
            try:
                import json
                with open(resolved_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    pins = data.get("pins", []) if isinstance(data, dict) else (data.get("object", {}).get("pins", []) if isinstance(data, dict) else [])
                    for pin in pins:
                        pkg_identity = pin.get("identity") or pin.get("package")
                        state = pin.get("state", {})
                        ver = state.get("version") or pin.get("state", {}).get("revision")
                        if pkg_identity:
                            deps.append(RawDependency(
                                name=pkg_identity,
                                version_spec=ver or "0.0.0",
                                ecosystem="Swift",
                                source_file=resolved_file.name
                            ))
            except Exception:
                pass

        if not deps and swift_file.exists():
            try:
                content = swift_file.read_text(encoding="utf-8")
                import re
                matches = re.findall(r'\.package\(\s*url:\s*"[^"]+/([^"/]+)(?:\.git)?"\s*,\s*from:\s*"([^"]+)"', content)
                for name, ver in matches:
                    deps.append(RawDependency(
                        name=name,
                        version_spec=ver,
                        ecosystem="Swift",
                        source_file=swift_file.name
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
                ecosystem="Swift",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://swiftpackageindex.com/api/packages/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("releases", [{}])[0].get("version") if isinstance(data, dict) else None
                return RegistryValidationResult(True, True, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
