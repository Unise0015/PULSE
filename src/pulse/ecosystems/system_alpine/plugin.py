"""
Alpine Linux System Package Ecosystem Provider for PULSE.
Parses /lib/apk/db/installed and APK manifest files.
"""

import sys
from pathlib import Path
from typing import List, Optional, Any
import httpx
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, PackageInfo, ProviderMetadata
)

# Absolute host path for apk installed DB
_HOST_APK_PATH = Path("/lib/apk/db/installed")


class SystemAlpinePlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="system_alpine",
            name="Alpine",
            ecosystem="Alpine",
            priority=20,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE}
        )

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            ecosystem_id="system_alpine",
            display_name="Alpine",
            registry_name="Alpine Packages",
            package_manager="apk",
            ecosystem_type="system",
            osv_ecosystem="Alpine",
            registry_url="https://pkgs.alpinelinux.org"
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)

        # Local-relative detection (always allowed)
        if (root / "lib/apk/db/installed").exists() or (root / "apk_installed").exists():
            return True

        # Host-absolute detection: ONLY if --include-host was explicitly set
        from pulse.state import AppState
        if AppState.INCLUDE_HOST and _HOST_APK_PATH.exists():
            return True

        # Context-aware warning: target resolves to "/" but flag was not set
        if not AppState.INCLUDE_HOST and _HOST_APK_PATH.exists():
            try:
                if root.resolve() == Path("/").resolve():
                    print(
                        "pulse: hint: Target is '/'. Use --include-host to scan host OS packages.",
                        file=sys.stderr
                    )
            except Exception:
                pass

        return False

    def _resolve_apk_file(self, root: Path) -> Optional[Path]:
        """Resolve which apk installed file to parse, respecting the host opt-in."""
        if (root / "lib/apk/db/installed").exists():
            return root / "lib/apk/db/installed"
        if (root / "apk_installed").exists():
            return root / "apk_installed"

        from pulse.state import AppState
        if AppState.INCLUDE_HOST and _HOST_APK_PATH.exists():
            return _HOST_APK_PATH

        return None

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        deps = []
        apk_file = self._resolve_apk_file(root)

        if apk_file is None:
            return deps

        is_host_origin = (apk_file == _HOST_APK_PATH)

        try:
            content = apk_file.read_text(encoding="utf-8")
            pkg_name = None
            pkg_ver = None
            for line in content.splitlines():
                if line.startswith("P:"):
                    pkg_name = line[2:].strip()
                elif line.startswith("V:"):
                    pkg_ver = line[2:].strip()
                elif not line.strip() and pkg_name and pkg_ver:
                    deps.append(RawDependency(
                        name=pkg_name,
                        version_spec=pkg_ver,
                        ecosystem="Alpine",
                        source_file=apk_file.name,
                        metadata={"origin": "host"} if is_host_origin else {}
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
                ecosystem="Alpine",
                dependency_type="DIRECT",
                source_file=r.source_file
            )
            for r in resolved_dependencies
        ]

    async def validate_registry_async(self, client: httpx.AsyncClient, name: str, version: Optional[str] = None) -> Any:
        from pulse.ecosystems.smart_detection import RegistryValidationResult
        try:
            resp = await client.get(f"https://pkgs.alpinelinux.org/packages?name={name}&branch=edge")
            if resp.status_code == 200:
                if "No matching packages found" in resp.text:
                    return RegistryValidationResult(False, False, None, False, 404)
                has_version = True
                if version and version not in resp.text:
                    has_version = False
                return RegistryValidationResult(True, has_version, None, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)
