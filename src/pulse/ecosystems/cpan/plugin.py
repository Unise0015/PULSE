"""
Perl CPAN Ecosystem Provider for PULSE.
Parses cpanfile and Makefile.PL. Validates against MetaCPAN registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class CpanPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="cpan",
            name="CPAN",
            ecosystem="CPAN",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="cpan",
            display_name="CPAN",
            registry_name="CPAN",
            package_manager="cpanm",
            ecosystem_type="application",
            osv_ecosystem="CPAN",
            registry_url="https://metacpan.org"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "cpanfile").exists() or (root / "Makefile.PL").exists() or (root / "META.json").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        cpanfile = root / "cpanfile"

        if cpanfile.exists():
            try:
                content = cpanfile.read_text(encoding="utf-8")
                import re
                matches = re.findall(r'requires\s+[\'"]([^\'"]+)[\'"]\s*(?:=>\s*[\'"]([^\'"]+)[\'"])?', content)
                for name, ver in matches:
                    deps.append(RawDependency(
                        name=name,
                        version_spec=ver or "0.0.0",
                        ecosystem="CPAN",
                        source_file=cpanfile.name
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
                ecosystem="CPAN",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://fastapi.metacpan.org/v1/release/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("version")
                has_version = True
                if version:
                    has_version = (version == latest)
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
