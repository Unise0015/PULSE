"""
Debian / Ubuntu System Package Ecosystem Provider for PULSE.
Parses dpkg status files and system package manifests.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class SystemDebianPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="system_debian",
            name="Debian",
            ecosystem="Debian",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="system_debian",
            display_name="Debian",
            registry_name="Debian Security Tracker",
            package_manager="apt",
            ecosystem_type="system",
            osv_ecosystem="Debian",
            registry_url="https://security-tracker.debian.org"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "var/lib/dpkg/status").exists() or (root / "dpkg.status").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        dpkg_file = root / "var/lib/dpkg/status" if (root / "var/lib/dpkg/status").exists() else (root / "dpkg.status")

        if dpkg_file.exists():
            try:
                content = dpkg_file.read_text(encoding="utf-8")
                pkg_name = None
                pkg_ver = None
                for line in content.splitlines():
                    if line.startswith("Package: "):
                        pkg_name = line.split("Package: ", 1)[1].strip()
                    elif line.startswith("Version: "):
                        pkg_ver = line.split("Version: ", 1)[1].strip()
                    elif not line.strip() and pkg_name and pkg_ver:
                        deps.append(RawDependency(
                            name=pkg_name,
                            version_spec=pkg_ver,
                            ecosystem="Debian",
                            source_file=dpkg_file.name
                        ))
                        pkg_name = None
                        pkg_ver = None
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
                ecosystem="Debian",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://sources.debian.org/api/src/{name}/")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("error"):
                    return RegistryValidationResult(False, False, None, False, 404)
                versions = data.get("versions", [])
                latest = versions[0].get("version") if versions else None
                has_version = True
                if version:
                    has_version = any(v.get("version") == version for v in versions)
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
