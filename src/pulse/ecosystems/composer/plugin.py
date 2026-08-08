import json
from pathlib import Path
from typing import List, Set
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class ComposerPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="composer",
            name="Composer",
            ecosystem="Packagist",
            priority=70,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.GRAPH}
        )

    def package_name_confidence(self, name: str) -> int:
        parts = name.split("/")
        if len(parts) == 2 and not name.startswith("@") and not name.startswith("github.com"):
            return 95
        return 0

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "composer.lock").exists() or (root / "composer.json").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        lock_file = root / "composer.lock"
        json_file = root / "composer.json"
        
        packages = []
        direct_deps = self._get_direct_deps(json_file)
        
        if lock_file.exists():
            try:
                data = json.loads(lock_file.read_text(encoding="utf-8"))
                all_pkgs = data.get("packages", []) + data.get("packages-dev", [])
                
                for pkg in all_pkgs:
                    name = pkg.get("name")
                    version = pkg.get("version")
                    if name and version:
                        clean_version = version.lstrip("v")
                        dep_type = "DIRECT" if name in direct_deps else "TRANSITIVE"
                        packages.append(RawDependency(
                            name=name,
                            version_spec=clean_version,
                            ecosystem="Packagist",
                            dependency_type=dep_type,
                            source_file=str(lock_file)
                        ))
            except Exception:
                pass
        else:
            if json_file.exists():
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    reqs = {**data.get("require", {}), **data.get("require-dev", {})}
                    for name, version in reqs.items():
                        if name == "php":
                            continue
                        clean_version = version.lstrip("^~>=< ")
                        packages.append(RawDependency(
                            name=name,
                            version_spec=clean_version,
                            ecosystem="Packagist",
                            dependency_type="DIRECT",
                            source_file=str(json_file)
                        ))
                except Exception:
                    pass
                    
        return packages

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
                ecosystem="Packagist",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        edges = []
        lock_file = root / "composer.lock"
        if lock_file.exists():
            try:
                data = json.loads(lock_file.read_text(encoding="utf-8"))
                all_pkgs = data.get("packages", []) + data.get("packages-dev", [])
                
                for pkg in all_pkgs:
                    parent_name = pkg.get("name")
                    requires = pkg.get("require", {})
                    if parent_name and requires:
                        for child_name in requires.keys():
                            if child_name == "php":
                                                      continue
                            edges.append(DependencyEdge(parent_name=parent_name, child_name=child_name))
            except Exception:
                pass
        return edges

    def _get_direct_deps(self, json_file: Path) -> Set[str]:
        direct = set()
        if json_file.exists():
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                reqs = data.get("require", {})
                reqs_dev = data.get("require-dev", {})
                for name in reqs.keys():
                    if name != "php":
                        direct.add(name)
                for name in reqs_dev.keys():
                    if name != "php":
                        direct.add(name)
            except Exception:
                pass
        return direct
