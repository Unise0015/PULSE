from typing import List, Optional
from pulse.domain.models import PackageInfo
from pulse.ecosystems.base import (
    EcosystemPlugin, PluginManifest, PluginCategory, Capability,
    ScanContext, RawDependency, ResolvedDependency, ProviderMetadata
)
from pulse.discoverers.system.linux import LinuxHostDiscoverer
from pulse.state import AppState

class HostSystemPlugin(EcosystemPlugin):
    """Unified Host System & OS Discovery Plugin."""

    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="system_host",
            name="Host System",
            ecosystem="Host",
            priority=10,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE}
        )

    def detect(self, context: ScanContext) -> bool:
        discoverer = LinuxHostDiscoverer()
        return AppState.SYSTEM_SCAN and discoverer.is_applicable()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        discoverer = LinuxHostDiscoverer()
        pkgs = discoverer.discover()
        raw = []
        for p in pkgs:
            raw.append(RawDependency(
                name=p.name,
                version_spec=p.version,
                ecosystem=p.ecosystem,
                dependency_type=p.dependency_type,
                source_file=p.source_file,
                metadata=p.metadata or {"origin": "host"}
            ))
        return raw

    def resolve(self, raw_dependencies: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        return [
            ResolvedDependency(
                name=r.name,
                resolved_version=r.version_spec,
                ecosystem=r.ecosystem,
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            )
            for r in raw_dependencies
        ]

    def normalize(self, resolved_dependencies: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        return [
            PackageInfo(
                name=r.name,
                version=r.resolved_version,
                ecosystem=r.ecosystem,
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            )
            for r in resolved_dependencies
        ]
