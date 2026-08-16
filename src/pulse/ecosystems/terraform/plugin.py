"""
Terraform / OpenTofu IaC Ecosystem Provider for PULSE.
Parses *.tf, .terraform.lock.hcl, and .tofu.lock.hcl. Validates against Terraform Registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class TerraformPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="terraform",
            name="Terraform",
            ecosystem="Terraform",
            priority=20,
            category=PluginCategory.INFRASTRUCTURE,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="terraform",
            display_name="Terraform",
            registry_name="Terraform Registry",
            package_manager="terraform",
            ecosystem_type="infrastructure",
            osv_ecosystem="Terraform",
            registry_url="https://registry.terraform.io"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / ".terraform.lock.hcl").exists() or (root / ".tofu.lock.hcl").exists() or any(root.glob("*.tf"))

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        lockfile = root / ".terraform.lock.hcl"

        if lockfile.exists():
            try:
                content = lockfile.read_text(encoding="utf-8")
                import re
                matches = re.findall(r'provider\s+"([^"]+)"\s*\{\s*version\s*=\s*"([^"]+)"', content)
                for name, ver in matches:
                    deps.append(RawDependency(
                        name=name,
                        version_spec=ver,
                        ecosystem="Terraform",
                        source_file=lockfile.name
                    ))
            except Exception:
                pass
        else:
            # Parse *.tf files
            import re
            for tf_file in root.glob("*.tf"):
                try:
                    content = tf_file.read_text(encoding="utf-8")
                    # Match source and version in terraform block
                    matches = re.findall(r'''source\s*=\s*["']([^"']+)["'][\s\S]*?version\s*=\s*["']([^"']+)["']''', content)
                    for src, ver in matches:
                        clean_ver = ver.lstrip("~>=< ")
                        deps.append(RawDependency(
                            name=src,
                            version_spec=clean_ver,
                            ecosystem="Terraform",
                            source_file=tf_file.name
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
                ecosystem="Terraform",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://registry.terraform.io/v1/providers/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("version")
                has_version = True
                if version:
                    versions = data.get("versions", [])
                    has_version = version in versions
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
