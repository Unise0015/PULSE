from pathlib import Path
from typing import List, Set
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class GoPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="go",
            name="Go",
            ecosystem="Go",
            priority=80,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE}
        )

    def package_name_confidence(self, name: str) -> int:
        if any(name.startswith(prefix) for prefix in ("github.com/", "golang.org/", "gopkg.in/")):
            return 100
        return 0

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "go.mod").exists() or (root / "go.sum").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        go_mod = root / "go.mod"
        go_sum = root / "go.sum"
        
        packages = []
        seen = set()
        
        if go_sum.exists():
            try:
                content = go_sum.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        if version.endswith("/go.mod"):
                            version = version[:-7]
                        
                        key = (name, version)
                        if key not in seen:
                            seen.add(key)
                            packages.append(RawDependency(
                                name=name,
                                version_spec=version,
                                ecosystem="Go",
                                dependency_type="TRANSITIVE",
                                source_file=str(go_sum)
                            ))
            except Exception:
                pass
                
        if not packages and go_mod.exists():
            try:
                content = go_mod.read_text(encoding="utf-8")
                in_require = False
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if line.startswith(")") and in_require:
                        in_require = False
                        continue
                    
                    if line.startswith("require"):
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[1]
                            version = parts[2]
                            packages.append(RawDependency(
                                name=name,
                                version_spec=version,
                                ecosystem="Go",
                                dependency_type="DIRECT",
                                source_file=str(go_mod)
                            ))
                    elif in_require:
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            packages.append(RawDependency(
                                name=name,
                                version_spec=version,
                                ecosystem="Go",
                                dependency_type="DIRECT",
                                source_file=str(go_mod)
                            ))
            except Exception:
                pass
                
        direct_deps = self._parse_go_mod_direct(go_mod)
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
                ecosystem="Go",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def _parse_go_mod_direct(self, go_mod: Path) -> Set[str]:
        direct = set()
        if not go_mod.exists():
            return direct
        try:
            content = go_mod.read_text(encoding="utf-8")
            in_require = False
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                if line.startswith("require ("):
                    in_require = True
                    continue
                if line.startswith(")") and in_require:
                    in_require = False
                    continue
                
                if line.startswith("require"):
                    parts = line.split()
                    if len(parts) >= 2:
                        direct.add(parts[1])
                elif in_require:
                    parts = line.split()
                    if len(parts) >= 1:
                        direct.add(parts[0])
        except Exception:
            pass
        return direct
