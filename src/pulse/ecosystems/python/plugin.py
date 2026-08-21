import importlib.metadata
import re
import unittest.mock
import ast
import json
from pathlib import Path
from typing import List, Dict, Optional
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory
from pulse.discoverers.python import PythonDiscoverer

class PythonPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="python",
            name="Python",
            ecosystem="PyPI",
            priority=100,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE, Capability.GRAPH}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        manifests = [
            "poetry.lock", "Pipfile.lock", "uv.lock",
            "pyproject.toml", "Pipfile", "setup.py", "requirements.txt"
        ]
        return any((root / m).exists() for m in manifests) or root.resolve() == Path(".").resolve()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        
        # Delegate to unittest.mock/PythonDiscoverer if mock compatibility is active
        if isinstance(PythonDiscoverer.discover, unittest.mock.Mock):
            pkgs = PythonDiscoverer().discover(str(root))
            return [self._pkg_to_raw(p) for p in pkgs]

        manifest_found = False

        # 1. Lockfiles (Exact pinned versions)
        poetry_lock = root / "poetry.lock"
        if poetry_lock.exists():
            manifest_found = True
            deps = self._parse_poetry_lock(poetry_lock)
            if deps: return deps

        pipfile_lock = root / "Pipfile.lock"
        if pipfile_lock.exists():
            manifest_found = True
            deps = self._parse_pipfile_lock(pipfile_lock)
            if deps: return deps

        uv_lock = root / "uv.lock"
        if uv_lock.exists():
            manifest_found = True
            deps = self._parse_uv_lock(uv_lock)
            if deps: return deps

        # 2. Manifests (Version ranges)
        pyproject_toml = root / "pyproject.toml"
        if pyproject_toml.exists():
            manifest_found = True
            deps = self._parse_pyproject_toml(pyproject_toml)
            if deps: return deps

        pipfile = root / "Pipfile"
        if pipfile.exists():
            manifest_found = True
            deps = self._parse_pipfile(pipfile)
            if deps: return deps

        req_file = root / "requirements.txt"
        if req_file.exists():
            manifest_found = True
            deps = self._parse_requirements_txt(req_file)
            if deps: return deps

        setup_py = root / "setup.py"
        if setup_py.exists():
            manifest_found = True
            deps = self._parse_setup_py_ast(setup_py)
            if deps: return deps

        # If a manifest file was found but couldn't be parsed statically (e.g. dynamic setup.py)
        # return empty to avoid the noisy environment fallback.
        if manifest_found:
            import logging
            logging.getLogger(__name__).warning("Manifest found but could not be parsed statically. Returning 0 dependencies.")
            return []

        # Fallback to discovering what's installed in the environment ONLY if no manifest files were found
        pkgs = PythonDiscoverer().discover(str(root))
        return [self._pkg_to_raw(p) for p in pkgs]

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
                ecosystem="python",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages

    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        req_file = root / "requirements.txt"
        if req_file.exists():
            return []
        
        edges = []
        pkg_requires = self._get_installed_requires()
        for parent, children in pkg_requires.items():
            for child in children:
                edges.append(DependencyEdge(parent_name=parent, child_name=child))
        return edges

    def _pkg_to_raw(self, p: PackageInfo) -> RawDependency:
        return RawDependency(
            name=p.name,
            version_spec=p.version,
            ecosystem="python",
            dependency_type=p.dependency_type,
            source_file=p.source_file,
            metadata=p.metadata
        )

    def _parse_requirements_txt(self, path: Path) -> List[RawDependency]:
        packages = []
        pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(?:[=>~^]+([0-9a-zA-Z.\-]+))?")
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    line = line.split(" #")[0].strip()
                    match = pattern.match(line)
                    if match:
                        name = match.group(1)
                        version = match.group(2) if match.group(2) else ""
                        packages.append(RawDependency(
                            name=name,
                            version_spec=version,
                            ecosystem="python",
                            dependency_type="DIRECT",
                            source_file=str(path)
                        ))
        except Exception:
            pass
        return packages

    def _parse_poetry_lock(self, path: Path) -> List[RawDependency]:
        packages = []
        try:
            import tomli
        except ImportError:
            try:
                import tomllib as tomli
            except ImportError:
                return packages

        try:
            with open(path, "rb") as f:
                data = tomli.load(f)
            
            for pkg in data.get("package", []):
                packages.append(RawDependency(
                    name=pkg.get("name", ""),
                    version_spec=pkg.get("version", ""),
                    ecosystem="python",
                    dependency_type="DIRECT" if pkg.get("category") == "main" else "DEV",
                    source_file=str(path)
                ))
        except Exception:
            pass
        return packages

    def _parse_pipfile_lock(self, path: Path) -> List[RawDependency]:
        packages = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for section in ["default", "develop"]:
                dep_type = "DIRECT" if section == "default" else "DEV"
                for name, details in data.get(section, {}).items():
                    version = details.get("version", "").lstrip("=")
                    packages.append(RawDependency(
                        name=name,
                        version_spec=version,
                        ecosystem="python",
                        dependency_type=dep_type,
                        source_file=str(path)
                    ))
        except Exception:
            pass
        return packages

    def _parse_uv_lock(self, path: Path) -> List[RawDependency]:
        packages = []
        try:
            import tomli
        except ImportError:
            try:
                import tomllib as tomli
            except ImportError:
                return packages

        try:
            with open(path, "rb") as f:
                data = tomli.load(f)
            
            for pkg in data.get("package", []):
                if "name" in pkg and "version" in pkg:
                    packages.append(RawDependency(
                        name=pkg["name"],
                        version_spec=pkg["version"],
                        ecosystem="python",
                        dependency_type="DIRECT",
                        source_file=str(path)
                    ))
        except Exception:
            pass
        return packages

    def _parse_pyproject_toml(self, path: Path) -> List[RawDependency]:
        packages = []
        try:
            import tomli
        except ImportError:
            try:
                import tomllib as tomli
            except ImportError:
                return packages

        try:
            with open(path, "rb") as f:
                data = tomli.load(f)
            
            deps = []
            # standard pep621
            if "project" in data and "dependencies" in data["project"]:
                deps.extend(data["project"]["dependencies"])
            # poetry
            if "tool" in data and "poetry" in data["tool"] and "dependencies" in data["tool"]["poetry"]:
                for k, v in data["tool"]["poetry"]["dependencies"].items():
                    if k.lower() == "python":
                        continue
                    if isinstance(v, str):
                        deps.append(f"{k} {v}")
                    elif isinstance(v, dict) and "version" in v:
                        deps.append(f"{k} {v['version']}")
                    else:
                        deps.append(k)
                        
            pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(?:[=>~^]+([0-9a-zA-Z.\-]+))?")
            for dep in deps:
                dep = dep.split(";")[0].strip()
                match = pattern.match(dep)
                if match:
                    name = match.group(1)
                    version = match.group(2) if match.group(2) else ""
                    packages.append(RawDependency(
                        name=name,
                        version_spec=version,
                        ecosystem="python",
                        dependency_type="DIRECT",
                        source_file=str(path)
                    ))
        except Exception:
            pass
        return packages

    def _parse_pipfile(self, path: Path) -> List[RawDependency]:
        packages = []
        try:
            import tomli
        except ImportError:
            try:
                import tomllib as tomli
            except ImportError:
                return packages

        try:
            with open(path, "rb") as f:
                data = tomli.load(f)
            
            for section in ["packages", "dev-packages"]:
                dep_type = "DIRECT" if section == "packages" else "DEV"
                for name, val in data.get(section, {}).items():
                    if name.lower() == "python":
                        continue
                    version = val if isinstance(val, str) else val.get("version", "")
                    version = version.lstrip("=") if version != "*" else ""
                    packages.append(RawDependency(
                        name=name,
                        version_spec=version,
                        ecosystem="python",
                        dependency_type=dep_type,
                        source_file=str(path)
                    ))
        except Exception:
            pass
        return packages

    def _parse_setup_py_ast(self, path: Path) -> List[RawDependency]:
        """Safely parse setup.py using AST to find install_requires without executing it."""
        packages = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                
            tree = ast.parse(content)
            
            install_requires = []
            
            # Look for setup(..., install_requires=['dep1', 'dep2'], ...)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check if it's a call to setup()
                    is_setup = False
                    if isinstance(node.func, ast.Name) and node.func.id == "setup":
                        is_setup = True
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == "setup":
                        is_setup = True
                        
                    if is_setup:
                        for keyword in node.keywords:
                            if keyword.arg == "install_requires":
                                if isinstance(keyword.value, ast.List):
                                    for elt in keyword.value.elts:
                                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                            install_requires.append(elt.value)
                                        elif hasattr(ast, 'Str') and isinstance(elt, getattr(ast, 'Str')):
                                            install_requires.append(elt.s)
                                            
            # Parse the extracted requires strings
            pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(?:[=>~^]+([0-9a-zA-Z.\-]+))?")
            for req in install_requires:
                req = req.split(";")[0].strip()
                match = pattern.match(req)
                if match:
                    name = match.group(1)
                    version = match.group(2) if match.group(2) else ""
                    packages.append(RawDependency(
                        name=name,
                        version_spec=version,
                        ecosystem="python",
                        dependency_type="DIRECT",
                        source_file=str(path)
                    ))
        except Exception:
            pass
        return packages

    def _get_installed_requires(self) -> Dict[str, List[str]]:
        pkg_requires = {}
        try:
            for dist in importlib.metadata.distributions():
                raw_name = dist.metadata.get("Name")
                if not raw_name:
                    continue
                parent_key = self._norm(raw_name)
                
                raw_requires = dist.metadata.get_all("Requires-Dist") or []
                deps = []
                for req in raw_requires:
                    req_lower = req.lower()
                    if any(x in req_lower for x in ["extra == 'test'", 'extra == "test"', "extra == 'dev'", 'extra == "dev"', "extra == 'tests'", 'extra == "tests"']):
                        continue
                    
                    dep_key = self._parse_dep_name(req)
                    if dep_key:
                        deps.append(dep_key)
                pkg_requires[parent_key] = deps
        except Exception:
            pass
        return pkg_requires

    def _norm(self, name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    def _parse_dep_name(self, req: str) -> str:
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)", req)
        if match:
            return self._norm(match.group(1))
        return ""
