"""
Parser Registry for PULSE CLI.
Maps logical DependencyFileType enum variants to dedicated file parser functions.
"""

import json
import re
from pathlib import Path
from typing import List, Callable, Dict
from pulse.domain.models import PackageInfo
from pulse.parsers.file_detector import DependencyFileType


class ParserRegistry:
    """Registry mapping DependencyFileType to specific file parser functions."""

    _parsers: Dict[DependencyFileType, Callable[[Path], List[PackageInfo]]] = {}

    @classmethod
    def register(cls, file_type: DependencyFileType, parser_fn: Callable[[Path], List[PackageInfo]]):
        cls._parsers[file_type] = parser_fn

    @classmethod
    def get_parser(cls, file_type: DependencyFileType) -> Callable[[Path], List[PackageInfo]]:
        if file_type in cls._parsers:
            return cls._parsers[file_type]
        raise ValueError(f"No parser registered for file type: {file_type}")

    @classmethod
    def parse(cls, path: Path, file_type: DependencyFileType) -> List[PackageInfo]:
        parser_fn = cls.get_parser(file_type)
        return parser_fn(path)


# Individual File Parsers that parse physical Path directly


def parse_pyproject_toml(path: Path) -> List[PackageInfo]:
    """Parse pyproject.toml file for dependencies."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        import re
        
        # Look for standard PEP 621 dependencies
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("["):
                # We enter dependencies block
                if line == "[project.dependencies]" or line == "[tool.poetry.dependencies]":
                    in_deps = True
                else:
                    in_deps = False
                continue
                
            if in_deps and line:
                if line.startswith("#"): continue
                
                # PEP 621 usually uses array of strings: "requests>=2.0"
                # Poetry uses key-value: requests = "^2.0"
                # Let's handle both
                
                # Poetry style
                if "=" in line:
                    parts = line.split("=", 1)
                    name = parts[0].strip().strip('"').strip("'")
                    version = parts[1].strip().strip(',').strip('"').strip("'").lstrip('^~>=<')
                    if name:
                        packages.append(PackageInfo(name=name, version=version, ecosystem="pypi", source_file=path.name))
                # PEP 621 style
                elif line.startswith('"') or line.startswith("'"):
                    val = line.strip(',').strip('"').strip("'")
                    match = re.match(r"^([a-zA-Z0-9_\-\.\[\]]+)(?:==|>=|<=|~=|!=|<|>|===|@)?\s*([a-zA-Z0-9_\-\.\*]+)?", val)
                    if match:
                        name = match.group(1).strip()
                        if "[" in name:
                            name = name.split("[")[0]
                        version = match.group(2).strip() if match.group(2) else "unknown"
                        packages.append(PackageInfo(name=name, version=version, ecosystem="pypi", source_file=path.name))
                        
    except Exception as e:
        raise ValueError(f"Failed to parse pyproject.toml '{path.name}': {e}")

    return packages

def parse_python_requirements_file(path: Path) -> List[PackageInfo]:
    """Parse Python requirements file from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("-"):
                    continue

                match = re.match(r"^([a-zA-Z0-9_\-\.\[\]]+)(?:==|>=|<=|~=|!=|<|>|===|@)?\s*([a-zA-Z0-9_\-\.\*]+)?", clean_line)
                if match:
                    pkg_name = match.group(1).strip()
                    version = match.group(2).strip() if match.group(2) else "unknown"

                    if "[" in pkg_name:
                        pkg_name = pkg_name.split("[")[0]

                    packages.append(PackageInfo(
                        name=pkg_name,
                        version=version,
                        ecosystem="pypi",
                        source_file=path.name
                    ))
    except Exception as e:
        raise ValueError(f"Failed to parse Python requirements file '{path.name}': {e}")

    return packages


def parse_package_json_file(path: Path) -> List[PackageInfo]:
    """Parse package.json file from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})

        all_deps = {**deps, **dev_deps}
        for name, spec in all_deps.items():
            version = str(spec).lstrip("^~>=<v").strip() if spec else "unknown"
            packages.append(PackageInfo(
                name=name,
                version=version,
                ecosystem="npm",
                source_file=path.name
            ))
    except Exception as e:
        raise ValueError(f"Failed to parse package.json file '{path.name}': {e}")

    return packages


def parse_npm_lock_file(path: Path) -> List[PackageInfo]:
    """Parse package-lock.json file from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "packages" in data and isinstance(data["packages"], dict):
            for pkg_path, info in data["packages"].items():
                if not pkg_path:  # Root package
                    continue
                name = info.get("name") or pkg_path.replace("node_modules/", "").split("node_modules/")[-1]
                version = info.get("version", "unknown")
                if name:
                    packages.append(PackageInfo(name=name, version=version, ecosystem="npm", source_file=path.name))
        elif "dependencies" in data and isinstance(data["dependencies"], dict):
            for name, info in data["dependencies"].items():
                version = info.get("version", "unknown") if isinstance(info, dict) else str(info)
                packages.append(PackageInfo(name=name, version=version, ecosystem="npm", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse package-lock.json file '{path.name}': {e}")

    return packages


def parse_cargo_file(path: Path) -> List[PackageInfo]:
    """Parse Cargo.lock / Cargo.toml file from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        blocks = content.split("[[package]]")
        for b in blocks[1:]:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', b)
            ver_m = re.search(r'version\s*=\s*"([^"]+)"', b)
            if name_m and ver_m:
                packages.append(PackageInfo(
                    name=name_m.group(1),
                    version=ver_m.group(1),
                    ecosystem="cargo",
                    source_file=path.name
                ))
    except Exception as e:
        raise ValueError(f"Failed to parse Cargo file '{path.name}': {e}")

    return packages


def parse_go_file(path: Path) -> List[PackageInfo]:
    """Parse go.mod / go.sum file from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//") or line.startswith("module") or line.startswith("go "):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    packages.append(PackageInfo(name=name, version=version, ecosystem="go", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse Go file '{path.name}': {e}")

    return packages


def parse_ruby_file(path: Path) -> List[PackageInfo]:
    """Parse Gemfile / Gemfile.lock from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        in_specs = False
        for line in content.splitlines():
            if "specs:" in line:
                in_specs = True
                continue
            if in_specs:
                if line and not line.startswith("    "):
                    in_specs = False
                    continue
                match = re.search(r'^\s{4}([a-zA-Z0-9_\-\.]+)\s+\(([^)]+)\)', line)
                if match:
                    packages.append(PackageInfo(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem="rubygems",
                        source_file=path.name
                    ))
    except Exception as e:
        raise ValueError(f"Failed to parse Gemfile '{path.name}': {e}")

    return packages


def parse_composer_file(path: Path) -> List[PackageInfo]:
    """Parse composer.json / composer.lock from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        pkgs = data.get("packages", [])
        if isinstance(pkgs, list):
            for p in pkgs:
                name = p.get("name")
                version = p.get("version", "unknown").lstrip("v")
                if name:
                    packages.append(PackageInfo(name=name, version=version, ecosystem="packagist", source_file=path.name))
        elif isinstance(data.get("require"), dict):
            for name, ver in data["require"].items():
                if name != "php":
                    packages.append(PackageInfo(name=name, version=str(ver).lstrip("^~>=<v"), ecosystem="packagist", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse Composer file '{path.name}': {e}")

    return packages


def parse_maven_file(path: Path) -> List[PackageInfo]:
    """Parse pom.xml from path."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for dep in re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL):
            group_m = re.search(r'<groupId>(.*?)</groupId>', dep)
            artifact_m = re.search(r'<artifactId>(.*?)</artifactId>', dep)
            version_m = re.search(r'<version>(.*?)</version>', dep)

            if group_m and artifact_m:
                name = f"{group_m.group(1).strip()}:{artifact_m.group(1).strip()}"
                version = version_m.group(1).strip() if version_m else "unknown"
                packages.append(PackageInfo(name=name, version=version, ecosystem="maven", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse Maven pom.xml '{path.name}': {e}")

    return packages



def parse_yarn_lock_file(path: Path) -> List[PackageInfo]:
    """Parse yarn.lock custom format."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        blocks = content.split("\n\n")
        for block in blocks:
            if not block.strip() or block.startswith("#"): continue
            lines = block.strip().split("\n")
            header = lines[0].strip().rstrip(":")
            # Header looks like: "@babel/core@^7.0.0", "@babel/core@~7.1.0":
            pkg_m = re.match(r'^"?(@?[^@]+)@', header)
            ver_m = re.search(r'\s*version\s+"?([^"\s]+)"?', block)
            if pkg_m and ver_m:
                packages.append(PackageInfo(name=pkg_m.group(1), version=ver_m.group(1), ecosystem="npm", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse yarn.lock '{path.name}': {e}")
    return packages

def parse_pnpm_lock_file(path: Path) -> List[PackageInfo]:
    """Parse pnpm-lock.yaml file."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"): continue
            if line.startswith("dependencies:") or line.startswith("devDependencies:"):
                in_deps = True
                continue
            elif line and not line.startswith(" ") and not line.startswith("-"):
                if "dependencies" not in line:
                    in_deps = False
            
            if in_deps and ":" in line:
                # e.g., "  react: 18.2.0"
                parts = stripped.split(":", 1)
                name = parts[0].strip().strip('"').strip("'")
                ver = parts[1].strip().strip('"').strip("'")
                if name and ver and not ver.startswith("{") and not ver.startswith("["):
                    packages.append(PackageInfo(name=name, version=ver, ecosystem="npm", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse pnpm-lock '{path.name}': {e}")
    return packages

def parse_pipfile(path: Path) -> List[PackageInfo]:
    """Parse Pipfile (TOML)."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("["):
                if line == "[packages]" or line == "[dev-packages]":
                    in_deps = True
                else:
                    in_deps = False
                continue
            if in_deps and "=" in line and not line.startswith("#"):
                parts = line.split("=", 1)
                name = parts[0].strip().strip('"').strip("'")
                val = parts[1].strip().strip(',').strip('"').strip("'")
                packages.append(PackageInfo(name=name, version=val, ecosystem="pypi", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse Pipfile '{path.name}': {e}")
    return packages

def parse_pipfile_lock(path: Path) -> List[PackageInfo]:
    """Parse Pipfile.lock (JSON)."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for cat in ["default", "develop"]:
            for name, info in data.get(cat, {}).items():
                ver = info.get("version", "unknown").lstrip("=")
                packages.append(PackageInfo(name=name, version=ver, ecosystem="pypi", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse Pipfile.lock '{path.name}': {e}")
    return packages

def parse_setup_py(path: Path) -> List[PackageInfo]:
    """Parse setup.py or setup.cfg for install_requires."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        reqs = re.findall(r"['\"]([a-zA-Z0-9_\-\.]+)[=><~!]*([^'\"]*)['\"]", content)
        for name, ver in reqs:
            if name and not " " in name and len(name) > 1:
                packages.append(PackageInfo(name=name, version=ver if ver else "unknown", ecosystem="pypi", source_file=path.name))
    except Exception as e:
        pass # setup.py regex is best effort
    return packages

def parse_gradle_build(path: Path) -> List[PackageInfo]:
    """Parse build.gradle dependencies."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        for line in content.splitlines():
            line = line.strip()
            # implementation 'group:name:version'
            m = re.search(r"['\"]([^:'\"]+):([^:'\"]+):([^:'\"]+)['\"]", line)
            if m:
                name = f"{m.group(1)}:{m.group(2)}"
                packages.append(PackageInfo(name=name, version=m.group(3), ecosystem="maven", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse Gradle file '{path.name}': {e}")
    return packages

def parse_mix_exs(path: Path) -> List[PackageInfo]:
    """Parse mix.exs dependencies."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        for line in content.splitlines():
            # {:phoenix, "~> 1.6.0"}
            m = re.search(r"\{:\s*([a-zA-Z0-9_]+)\s*,\s*\"[~><=]*\s*([^\"]+)\"", line)
            if m:
                packages.append(PackageInfo(name=m.group(1), version=m.group(2), ecosystem="hex", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse mix.exs '{path.name}': {e}")
    return packages

def parse_rebar_config(path: Path) -> List[PackageInfo]:
    """Parse rebar.config dependencies."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        m = re.search(r"\{deps,\s*\[(.*?)\]\}", content, re.DOTALL)
        if m:
            deps_str = m.group(1)
            for dep in re.findall(r"\{([a-zA-Z0-9_]+)\s*,", deps_str):
                packages.append(PackageInfo(name=dep, version="unknown", ecosystem="hex", source_file=path.name))
    except Exception as e:
        raise ValueError(f"Failed to parse rebar.config '{path.name}': {e}")
    return packages


# Register default parsers
ParserRegistry.register(DependencyFileType.PYTHON_REQUIREMENTS, parse_python_requirements_file)
ParserRegistry.register(DependencyFileType.PYPROJECT_TOML, parse_pyproject_toml)
ParserRegistry.register(DependencyFileType.PACKAGE_JSON, parse_package_json_file)
ParserRegistry.register(DependencyFileType.NPM_LOCK, parse_npm_lock_file)
ParserRegistry.register(DependencyFileType.YARN_LOCK, parse_yarn_lock_file)
ParserRegistry.register(DependencyFileType.PNPM_LOCK, parse_pnpm_lock_file)
ParserRegistry.register(DependencyFileType.CARGO_TOML, parse_cargo_file)
ParserRegistry.register(DependencyFileType.CARGO_LOCK, parse_cargo_file)
ParserRegistry.register(DependencyFileType.GO_MOD, parse_go_file)
ParserRegistry.register(DependencyFileType.GO_SUM, parse_go_file)
ParserRegistry.register(DependencyFileType.GEMFILE, parse_ruby_file)
ParserRegistry.register(DependencyFileType.GEMFILE_LOCK, parse_ruby_file)
ParserRegistry.register(DependencyFileType.COMPOSER_JSON, parse_composer_file)
ParserRegistry.register(DependencyFileType.COMPOSER_LOCK, parse_composer_file)
ParserRegistry.register(DependencyFileType.MAVEN_POM, parse_maven_file)

ParserRegistry.register(DependencyFileType.PIPFILE, parse_pipfile)
ParserRegistry.register(DependencyFileType.PIPFILE_LOCK, parse_pipfile_lock)
ParserRegistry.register(DependencyFileType.SETUP_PY, parse_setup_py)
ParserRegistry.register(DependencyFileType.GRADLE_BUILD, parse_gradle_build)
ParserRegistry.register(DependencyFileType.MIX_EXS, parse_mix_exs)
ParserRegistry.register(DependencyFileType.REBAR_CONFIG, parse_rebar_config)