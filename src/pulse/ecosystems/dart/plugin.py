"""
Dart / Flutter pub.dev Ecosystem Provider for PULSE.
Parses pubspec.yaml and pubspec.lock. Validates against pub.dev registry.
"""

from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)


class DartPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="dart",
            name="Dart",
            ecosystem="Pub",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.REGISTRY}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="dart",
            display_name="Dart",
            registry_name="pub.dev",
            package_manager="pub",
            ecosystem_type="application",
            osv_ecosystem="Pub",
            registry_url="https://pub.dev"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "pubspec.yaml").exists() or (root / "pubspec.lock").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        lockfile = root / "pubspec.lock"
        yamlfile = root / "pubspec.yaml"

        if lockfile.exists():
            try:
                content = lockfile.read_text(encoding="utf-8")
                try:
                    import yaml
                    data = yaml.safe_load(content)
                    packages = data.get("packages", {}) if isinstance(data, dict) else {}
                    for pkg_name, pkg_data in packages.items():
                        if isinstance(pkg_data, dict):
                            ver = pkg_data.get("version", "0.0.0")
                            deps.append(RawDependency(
                                name=pkg_name,
                                version_spec=ver,
                                ecosystem="Dart",
                                source_file=lockfile.name
                            ))
                except ImportError:
                    import re
                    matches = re.findall(r'([a-zA-Z0-9_-]+):[\s\S]*?version:\s*["\']?([^"\'\s]+)["\']?', content)
                    for name, ver in matches:
                        deps.append(RawDependency(name=name, version_spec=ver, ecosystem="Dart", source_file=lockfile.name))
            except Exception:
                pass

        if not deps and yamlfile.exists():
            try:
                content = yamlfile.read_text(encoding="utf-8")
                try:
                    import yaml
                    data = yaml.safe_load(content)
                    dev_deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
                    for name, spec in dev_deps.items():
                        if isinstance(spec, (str, int, float)):
                            clean_spec = str(spec).strip("^~ ")
                            deps.append(RawDependency(
                                name=name,
                                version_spec=clean_spec,
                                ecosystem="Dart",
                                source_file=yamlfile.name
                            ))
                except ImportError:
                    import re
                    in_deps = False
                    for line in content.splitlines():
                        line_str = line.strip()
                        if line_str == "dependencies:":
                            in_deps = True
                            continue
                        elif line_str.endswith(":") and not line.startswith(" "):
                            in_deps = False
                            continue
                        if in_deps and ":" in line_str and not line_str.startswith("#"):
                            name, spec = line_str.split(":", 1)
                            name = name.strip()
                            clean_spec = spec.strip().strip("'\"").strip("^~ ")
                            if name and clean_spec and not clean_spec.startswith("sdk"):
                                deps.append(RawDependency(
                                    name=name,
                                    version_spec=clean_spec,
                                    ecosystem="Dart",
                                    source_file=yamlfile.name
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
                ecosystem="Dart",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://pub.dev/api/packages/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("latest", {}).get("version")
                has_version = True
                if version:
                    versions = [v.get("version") for v in data.get("versions", [])]
                    has_version = version in versions
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
