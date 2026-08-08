import json
from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory
from pulse.discoverers.node import NodeDiscoverer

class NodePlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="npm",
            name="Node.js",
            ecosystem="npm",
            priority=90,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.GRAPH}
        )

    def package_name_confidence(self, name: str) -> int:
        if name.startswith("@") and "/" in name:
            return 100
        return 0

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "package.json").exists() or (root / "package-lock.json").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        pkgs = NodeDiscoverer().discover(str(root))
        raw_deps = []
        for p in pkgs:
            raw_deps.append(RawDependency(
                name=p.name,
                version_spec=p.version,
                ecosystem="npm",
                dependency_type=p.dependency_type,
                source_file=p.source_file,
                metadata=p.metadata
            ))
        return raw_deps

    def resolve(self, raw_dependencies: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        resolved = []
        for r in raw_dependencies:
            resolved.append(ResolvedDependency(
                name=r.name,
                resolved_version=r.version_spec,
                ecosystem=r.ecosystem,
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return resolved

    def normalize(self, resolved_dependencies: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        packages = []
        for r in resolved_dependencies:
            packages.append(PackageInfo(
                name=r.name,
                version=r.resolved_version,
                ecosystem="npm",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        edges = []
        package_lock_path = root / "package-lock.json"
        
        if package_lock_path.exists():
            try:
                with open(package_lock_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                    packages_dict = data.get("packages", {})
                    if packages_dict:
                        for key, info in packages_dict.items():
                            if not key:
                                continue
                            
                            name = key.split("node_modules/")[-1]
                            deps = info.get("dependencies", {})
                            for dep_name in deps.keys():
                                edges.append(DependencyEdge(parent_name=name, child_name=dep_name))
            except Exception:
                pass
        return edges
