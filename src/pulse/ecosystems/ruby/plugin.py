from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class RubyPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="ruby",
            name="Ruby",
            ecosystem="RubyGems",
            priority=75,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.GRAPH}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "Gemfile.lock").exists() or (root / "Gemfile").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        gemfile_lock = root / "Gemfile.lock"
        gemfile = root / "Gemfile"
        if gemfile_lock.exists():
            packages, _ = self._parse_gemfile_lock(gemfile_lock)
            return packages
        elif gemfile.exists():
            return self._parse_gemfile(gemfile)
        return []

    def _parse_gemfile(self, path: Path) -> List[RawDependency]:
        packages = []
        try:
            import re
            content = path.read_text(encoding="utf-8")
            # Match gem 'name', 'version' or gem "name", "~> version"
            matches = re.findall(r'''gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?''', content)
            for name, ver in matches:
                clean_ver = ver.lstrip("~>=< ") if ver else ""
                packages.append(RawDependency(
                    name=name,
                    version_spec=clean_ver,
                    ecosystem="RubyGems",
                    dependency_type="DIRECT",
                    source_file=str(path)
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
                ecosystem="RubyGems",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        gemfile_lock = root / "Gemfile.lock"
        _, edges = self._parse_gemfile_lock(gemfile_lock)
        return edges

    def _parse_gemfile_lock(self, path: Path) -> tuple[List[RawDependency], List[DependencyEdge]]:
        packages = []
        edges = []
        if not path.exists():
            return packages, edges
            
        try:
            content = path.read_text(encoding="utf-8")
            lines = content.splitlines()
            
            in_specs = False
            in_dependencies = False
            current_parent = None
            
            for line in lines:
                if not line:
                    continue
                stripped = line.strip()
                
                if line.startswith("DEPENDENCIES"):
                    in_specs = False
                    in_dependencies = True
                    continue
                elif line.startswith("GEM") or line.startswith("PLATFORMS") or line.startswith("BUNDLED WITH") or line.startswith("PATH") or line.startswith("GIT"):
                    if stripped != "specs:":
                        in_specs = False
                        in_dependencies = False
                    else:
                        in_specs = True
                    continue
                elif stripped == "specs:":
                    in_specs = True
                    continue
                
                if in_specs:
                    indent = len(line) - len(line.lstrip(' '))
                    if indent == 4:
                        parts = stripped.split(" (", 1)
                        if len(parts) == 2:
                            name = parts[0].strip()
                            version = parts[1].strip().rstrip(")")
                            current_parent = name
                            packages.append(RawDependency(
                                name=name,
                                version_spec=version,
                                ecosystem="RubyGems",
                                dependency_type="TRANSITIVE",
                                source_file=str(path)
                            ))
                    elif indent == 6 and current_parent:
                        parts = stripped.split(" (", 1)
                        dep_name = parts[0].strip()
                        edges.append(DependencyEdge(parent_name=current_parent, child_name=dep_name))
                        
                elif in_dependencies:
                    indent = len(line) - len(line.lstrip(' '))
                    if indent == 2:
                        parts = stripped.split(" (", 1)
                        name = parts[0].strip().rstrip("!")
                        for pkg in packages:
                            if pkg.name == name:
                                pkg.dependency_type = "DIRECT"
        except Exception:
            pass
            
        return packages, edges
