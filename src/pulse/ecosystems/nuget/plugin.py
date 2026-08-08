import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Any
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class NuGetPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="nuget",
            name="NuGet",
            ecosystem="NuGet",
            priority=55,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (
            len(list(root.glob("**/*.csproj"))) > 0
            or len(list(root.glob("**/packages.config"))) > 0
            or (root / "Directory.Packages.props").exists()
        )

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        raw_deps = []
        seen = set()
        
        # 1. Parse CPM properties if exists
        cpm_versions = self._parse_cpm_props(root)
        
        # 2. Find lockfiles
        lockfiles = list(root.glob("**/packages.lock.json"))
        for lock_path in lockfiles:
            deps = self._parse_lockfile(lock_path)
            for d in deps:
                key = (d.name, d.version_spec)
                if key not in seen:
                    seen.add(key)
                    raw_deps.append(d)
                    
        # 3. Find packages.config
        config_files = list(root.glob("**/packages.config"))
        for conf_path in config_files:
            deps = self._parse_config(conf_path)
            for d in deps:
                key = (d.name, d.version_spec)
                if key not in seen:
                    seen.add(key)
                    raw_deps.append(d)
                    
        # 4. Find csproj projects
        csproj_files = list(root.glob("**/*.csproj"))
        for csproj_path in csproj_files:
            deps = self._parse_csproj(csproj_path, cpm_versions)
            for d in deps:
                key = (d.name, d.version_spec)
                if key not in seen:
                    seen.add(key)
                    raw_deps.append(d)
                    
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
                ecosystem="NuGet",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def _parse_cpm_props(self, root: Path) -> Dict[str, str]:
        cpm_versions = {}
        props_path = root / "Directory.Packages.props"
        if not props_path.exists():
            return cpm_versions
        try:
            tree = ET.parse(props_path)
            el_root = tree.getroot()
            for pkg in el_root.findall(".//PackageVersion"):
                name = pkg.attrib.get("Include") or pkg.attrib.get("Update")
                version = pkg.attrib.get("Version")
                if name and version:
                    cpm_versions[name.lower()] = version
        except Exception:
            pass
        return cpm_versions

    def _parse_lockfile(self, lock_path: Path) -> List[RawDependency]:
        deps = []
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            # packages.lock.json contains dependency groups (e.g. .NETCoreApp)
            for group, target in data.get("dependencies", {}).items():
                # E.g., target frameworks dependencies
                for name, info in target.items():
                    resolved = info.get("resolved")
                    dep_type = info.get("type", "Direct")
                    norm_type = "DIRECT" if dep_type.lower() == "direct" else "TRANSITIVE"
                    if name and resolved:
                        deps.append(RawDependency(
                            name=name,
                            version_spec=resolved,
                            ecosystem="NuGet",
                            dependency_type=norm_type,
                            source_file=str(lock_path)
                        ))
        except Exception:
            pass
        return deps

    def _parse_config(self, conf_path: Path) -> List[RawDependency]:
        deps = []
        try:
            tree = ET.parse(conf_path)
            el_root = tree.getroot()
            for pkg in el_root.findall("package"):
                name = pkg.attrib.get("id")
                version = pkg.attrib.get("version")
                if name and version:
                    deps.append(RawDependency(
                        name=name,
                        version_spec=version,
                        ecosystem="NuGet",
                        dependency_type="DIRECT",
                        source_file=str(conf_path)
                    ))
        except Exception:
            pass
        return deps

    def _parse_csproj(self, csproj_path: Path, cpm_versions: Dict[str, str]) -> List[RawDependency]:
        deps = []
        try:
            tree = ET.parse(csproj_path)
            el_root = tree.getroot()
            for pr in el_root.findall(".//PackageReference"):
                name = pr.attrib.get("Include") or pr.attrib.get("Update")
                version = pr.attrib.get("Version")
                
                if name:
                    name_lower = name.lower()
                    if not version:
                        # Fallback to CPM
                        version = cpm_versions.get(name_lower, "")
                    if version:
                        deps.append(RawDependency(
                            name=name,
                            version_spec=version,
                            ecosystem="NuGet",
                            dependency_type="DIRECT",
                            source_file=str(csproj_path)
                        ))
        except Exception:
            pass
        return deps
