import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import List, Dict, Set, Any, Tuple
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class MavenPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="maven",
            name="Maven",
            ecosystem="Maven",
            priority=60,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.GRAPH}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "pom.xml").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        raw_deps = []
        poms = self._find_all_poms(root)
        
        # Build global property and dependencyManagement registries across all modules
        global_properties = {}
        dep_management = {}
        
        # First pass: collect parent/reactor properties & dependencyManagement
        for pom_path in poms:
            props, dep_mgmt = cls_collect_metadata(pom_path)
            global_properties.update(props)
            dep_management.update(dep_mgmt)
            
        # Second pass: parse actual dependencies
        for pom_path in poms:
            raw_deps.extend(self._parse_dependencies(pom_path, global_properties, dep_management))
            
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
                ecosystem="Maven",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        # Maven dependency resolution builds direct lists. We can map parent pom -> module dependencies
        edges = []
        poms = self._find_all_poms(root)
        for pom_path in poms:
            try:
                tree = ET.parse(pom_path)
                root_el = tree.getroot()
                ns = self._get_ns(root_el)
                
                # Identify project artifact coordinate
                g = root_el.find(f"{ns}groupId")
                a = root_el.find(f"{ns}artifactId")
                group_id = g.text.strip() if g is not None else ""
                artifact_id = a.text.strip() if a is not None else ""
                
                if not group_id:
                    parent = root_el.find(f"{ns}parent")
                    if parent is not None:
                        pg = parent.find(f"{ns}groupId")
                        group_id = pg.text.strip() if pg is not None else ""
                
                if group_id and artifact_id:
                    parent_coord = f"{group_id}:{artifact_id}"
                    deps_el = root_el.find(f"{ns}dependencies")
                    if deps_el is not None:
                        for dep in deps_el.findall(f"{ns}dependency"):
                            dg = dep.find(f"{ns}groupId")
                            da = dep.find(f"{ns}artifactId")
                            if dg is not None and da is not None:
                                child_coord = f"{dg.text.strip()}:{da.text.strip()}"
                                edges.append(DependencyEdge(parent_name=parent_coord, child_name=child_coord))
            except Exception:
                pass
        return edges

    def _find_all_poms(self, root: Path) -> List[Path]:
        return list(root.glob("**/pom.xml"))

    def _get_ns(self, element) -> str:
        if element.tag.startswith("{"):
            return element.tag.split("}")[0] + "}"
        return ""

    def _parse_dependencies(self, pom_path: Path, global_properties: dict, dep_management: dict) -> List[RawDependency]:
        deps = []
        try:
            tree = ET.parse(pom_path)
            root_el = tree.getroot()
            ns = self._get_ns(root_el)
            
            # Resolve local properties
            local_properties = {}
            # Project defaults
            g_el = root_el.find(f"{ns}groupId")
            a_el = root_el.find(f"{ns}artifactId")
            v_el = root_el.find(f"{ns}version")
            
            group_id = g_el.text.strip() if g_el is not None else ""
            artifact_id = a_el.text.strip() if a_el is not None else ""
            version = v_el.text.strip() if v_el is not None else ""
            
            parent = root_el.find(f"{ns}parent")
            if parent is not None:
                if not group_id:
                    pg = parent.find(f"{ns}groupId")
                    group_id = pg.text.strip() if pg is not None else ""
                if not version:
                    pv = parent.find(f"{ns}version")
                    version = pv.text.strip() if pv is not None else ""
            
            local_properties["project.groupId"] = group_id
            local_properties["project.artifactId"] = artifact_id
            local_properties["project.version"] = version
            local_properties["pom.version"] = version
            local_properties["pom.groupId"] = group_id
            
            props_el = root_el.find(f"{ns}properties")
            if props_el is not None:
                for p in props_el:
                    tag_name = p.tag.split("}")[-1]
                    if p.text:
                        local_properties[tag_name] = p.text.strip()
            
            all_props = {**global_properties, **local_properties}
            
            # Read `<dependencies>` section
            deps_el = root_el.find(f"{ns}dependencies")
            if deps_el is not None:
                for dep in deps_el.findall(f"{ns}dependency"):
                    dg = dep.find(f"{ns}groupId")
                    da = dep.find(f"{ns}artifactId")
                    dv = dep.find(f"{ns}version")
                    ds = dep.find(f"{ns}scope")
                    
                    if dg is not None and da is not None:
                        d_group = self._substitute_properties(dg.text.strip(), all_props)
                        d_artifact = self._substitute_properties(da.text.strip(), all_props)
                        
                        d_version = ""
                        if dv is not None:
                            d_version = self._substitute_properties(dv.text.strip(), all_props)
                        else:
                            # Resolve via dependencyManagement
                            d_version = dep_management.get(f"{d_group}:{d_artifact}", "")
                            
                        d_scope = ds.text.strip() if ds is not None else "compile"
                        
                        deps.append(RawDependency(
                            name=f"{d_group}:{d_artifact}",
                            version_spec=d_version,
                            ecosystem="Maven",
                            dependency_type="DIRECT",
                            source_file=str(pom_path),
                            metadata={"scope": d_scope}
                        ))
        except Exception:
            pass
        return deps

    def _substitute_properties(self, text: str, properties: dict) -> str:
        pattern = re.compile(r"\$\{([^}]+)\}")
        while True:
            match = pattern.search(text)
            if not match:
                break
            prop_name = match.group(1)
            prop_val = properties.get(prop_name, "")
            if not prop_val:
                # Break to avoid infinite loop on unresolved property
                break
            text = text.replace(match.group(0), prop_val)
        return text

def cls_collect_metadata(pom_path: Path) -> Tuple[dict, dict]:
    properties = {}
    dep_management = {}
    try:
        tree = ET.parse(pom_path)
        root_el = tree.getroot()
        tag = root_el.tag
        ns = ""
        if tag.startswith("{"):
            ns = tag.split("}")[0] + "}"
            
        # Parse `<properties>`
        props_el = root_el.find(f"{ns}properties")
        if props_el is not None:
            for p in props_el:
                tag_name = p.tag.split("}")[-1]
                if p.text:
                    properties[tag_name] = p.text.strip()
                    
        # Parse `<dependencyManagement>`
        dep_mgmt_el = root_el.find(f"{ns}dependencyManagement")
        if dep_mgmt_el is not None:
            deps_el = dep_mgmt_el.find(f"{ns}dependencies")
            if deps_el is not None:
                for dep in deps_el.findall(f"{ns}dependency"):
                    dg = dep.find(f"{ns}groupId")
                    da = dep.find(f"{ns}artifactId")
                    dv = dep.find(f"{ns}version")
                    if dg is not None and da is not None and dv is not None:
                        dep_management[f"{dg.text.strip()}:{da.text.strip()}"] = dv.text.strip()
    except Exception:
        pass
    return properties, dep_management
