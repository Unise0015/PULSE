from pathlib import Path
from typing import List, Set
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class RustPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="rust",
            name="Rust",
            ecosystem="crates.io",
            priority=85,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.GRAPH}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "Cargo.lock").exists() or (root / "Cargo.toml").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        cargo_lock = root / "Cargo.lock"
        cargo_toml = root / "Cargo.toml"
        
        packages, _ = self._parse_cargo_lock(cargo_lock)
        
        if not packages and cargo_toml.exists():
            direct_deps = self._get_direct_deps_cargo_with_versions(cargo_toml)
            for dep, ver in direct_deps.items():
                packages.append(RawDependency(
                    name=dep,
                    version_spec=ver,
                    ecosystem="crates.io",
                    dependency_type="DIRECT",
                    source_file=str(cargo_toml)
                ))
            return packages
            
        direct_deps = self._get_direct_deps_cargo(cargo_toml)
        for pkg in packages:
            if pkg.name in direct_deps:
                pkg.dependency_type = "DIRECT"
                
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
                ecosystem="crates.io",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        cargo_lock = root / "Cargo.lock"
        _, edges = self._parse_cargo_lock(cargo_lock)
        return edges

    def _parse_cargo_lock(self, path: Path) -> tuple[List[RawDependency], List[DependencyEdge]]:
        packages = []
        edges = []
        if not path.exists():
            return packages, edges
        
        try:
            content = path.read_text(encoding="utf-8")
            blocks = content.split("[[package]]")
            for block in blocks[1:]:
                lines = block.strip().splitlines()
                pkg_name = None
                pkg_version = None
                deps = []
                in_deps = False
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("[") and not line.startswith("[["):
                        in_deps = False
                        continue
                    
                    if not in_deps:
                        if line.startswith("name ="):
                            pkg_name = line.split("=", 1)[1].strip().strip('"')
                        elif line.startswith("version ="):
                            pkg_version = line.split("=", 1)[1].strip().strip('"')
                        elif line.startswith("dependencies ="):
                            in_deps = True
                            right = line.split("=", 1)[1].strip()
                            if right.startswith("[") and right.endswith("]"):
                                dep_list = right[1:-1].split(",")
                                for d in dep_list:
                                    d = d.strip().strip('"')
                                    dep_name = d.split()[0] if d else ""
                                    if dep_name:
                                        deps.append(dep_name)
                                in_deps = False
                    else:
                        if line.startswith("]"):
                            in_deps = False
                        else:
                            dep_name = line.strip().strip(",").strip('"').split()[0]
                            if dep_name:
                                deps.append(dep_name)
                
                if pkg_name and pkg_version:
                    packages.append(RawDependency(
                        name=pkg_name,
                        version_spec=pkg_version,
                        ecosystem="crates.io",
                        dependency_type="TRANSITIVE",
                        source_file=str(path)
                    ))
                    for dep in deps:
                        edges.append(DependencyEdge(parent_name=pkg_name, child_name=dep))
        except Exception:
            pass
        return packages, edges

    def _get_direct_deps_cargo_with_versions(self, toml_path: Path) -> dict:
        deps = {}
        if not toml_path.exists():
            return deps
        try:
            import re
            content = toml_path.read_text(encoding="utf-8")
            lines = content.splitlines()
            in_deps_section = False
            for line in lines:
                line = line.strip()
                if line.startswith("["):
                    sec = line.lower()
                    if "dependencies" in sec:
                        in_deps_section = True
                    else:
                        in_deps_section = False
                    continue
                if in_deps_section and "=" in line and not line.startswith("#"):
                    left, right = line.split("=", 1)
                    dep_name = left.strip().strip('"').strip("'")
                    ver = ""
                    # Check string version: "1.0" or { version = "1.0" }
                    ver_match = re.search(r'''["']([0-9][^"']*)["']''', right)
                    if ver_match:
                        ver = ver_match.group(1).lstrip("^~>=< ")
                    if dep_name:
                        deps[dep_name] = ver
        except Exception:
            pass
        return deps

    def _get_direct_deps_cargo(self, toml_path: Path) -> Set[str]:
        direct = set()
        if not toml_path.exists():
            return direct
        try:
            content = toml_path.read_text(encoding="utf-8")
            lines = content.splitlines()
            in_deps_section = False
            for line in lines:
                line = line.strip()
                if line.startswith("["):
                    sec = line.lower()
                    if "dependencies" in sec:
                        in_deps_section = True
                    else:
                        in_deps_section = False
                    continue
                if in_deps_section and "=" in line and not line.startswith("#"):
                    dep_name = line.split("=", 1)[0].strip().strip('"').strip("'")
                    if dep_name:
                        direct.add(dep_name)
        except Exception:
            pass
        return direct
