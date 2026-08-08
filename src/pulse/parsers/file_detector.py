"""
Dependency File Type Detector for PULSE CLI.
Identifies logical dependency file types independently from exact physical filenames.
"""

import os
import re
import json
from enum import Enum
from pathlib import Path
from typing import Optional


class DependencyFileType(Enum):
    PYTHON_REQUIREMENTS = "python_requirements"
    PACKAGE_JSON = "package_json"
    NPM_LOCK = "npm_lock"
    YARN_LOCK = "yarn_lock"
    PNPM_LOCK = "pnpm_lock"
    CARGO_TOML = "cargo_toml"
    CARGO_LOCK = "cargo_lock"
    GO_MOD = "go_mod"
    GO_SUM = "go_sum"
    GEMFILE = "gemfile"
    GEMFILE_LOCK = "gemfile_lock"
    COMPOSER_JSON = "composer_json"
    COMPOSER_LOCK = "composer_lock"
    MAVEN_POM = "maven_pom"
    UNKNOWN = "unknown"


class DependencyFileDetector:
    """Detects dependency file type independently from exact physical filename."""

    EXACT_MAP = {
        "requirements.txt": DependencyFileType.PYTHON_REQUIREMENTS,
        "requirements.lock": DependencyFileType.PYTHON_REQUIREMENTS,
        "requirements.in": DependencyFileType.PYTHON_REQUIREMENTS,
        "pipfile": DependencyFileType.PYTHON_REQUIREMENTS,
        "pyproject.toml": DependencyFileType.PYTHON_REQUIREMENTS,
        "package.json": DependencyFileType.PACKAGE_JSON,
        "package-lock.json": DependencyFileType.NPM_LOCK,
        "yarn.lock": DependencyFileType.YARN_LOCK,
        "pnpm-lock.yaml": DependencyFileType.PNPM_LOCK,
        "cargo.toml": DependencyFileType.CARGO_TOML,
        "cargo.lock": DependencyFileType.CARGO_LOCK,
        "go.mod": DependencyFileType.GO_MOD,
        "go.sum": DependencyFileType.GO_SUM,
        "gemfile": DependencyFileType.GEMFILE,
        "gemfile.lock": DependencyFileType.GEMFILE_LOCK,
        "composer.json": DependencyFileType.COMPOSER_JSON,
        "composer.lock": DependencyFileType.COMPOSER_LOCK,
        "pom.xml": DependencyFileType.MAVEN_POM,
    }

    @classmethod
    def detect(cls, path: Path) -> DependencyFileType:
        if isinstance(path, str):
            path = Path(path)

        name = path.name.lower().strip()

        # Step 1: Exact well-known filename
        if name in cls.EXACT_MAP:
            return cls.EXACT_MAP[name]

        # Step 2: Recognized Filename Patterns (regex)
        if re.search(r"^requirements(?:[-_.\s\(\)\d].*)?(?:\.txt|\.lock|\.in)?$", name):
            return DependencyFileType.PYTHON_REQUIREMENTS

        if re.search(r"^package-lock(?:[-_.\s\(\)\d].*)?\.json$", name):
            return DependencyFileType.NPM_LOCK

        if re.search(r"^package(?:[-_.\s\(\)\d].*)?\.json$", name):
            return DependencyFileType.PACKAGE_JSON

        if re.search(r"^cargo(?:[-_.\s\(\)\d].*)?\.toml$", name):
            return DependencyFileType.CARGO_TOML

        if re.search(r"^cargo(?:[-_.\s\(\)\d].*)?\.lock$", name):
            return DependencyFileType.CARGO_LOCK

        if re.search(r"^go(?:[-_.\s\(\)\d].*)?\.mod$", name):
            return DependencyFileType.GO_MOD

        if re.search(r"^go(?:[-_.\s\(\)\d].*)?\.sum$", name):
            return DependencyFileType.GO_SUM

        if "gemfile.lock" in name or re.search(r"^gemfile.*\.lock.*$", name):
            return DependencyFileType.GEMFILE_LOCK

        if re.search(r"^gemfile(?:[-_.\s\(\)\d].*)?$", name) and "lock" not in name:
            return DependencyFileType.GEMFILE

        if re.search(r"^composer(?:[-_.\s\(\)\d].*)?\.lock$", name):
            return DependencyFileType.COMPOSER_LOCK

        if re.search(r"^composer(?:[-_.\s\(\)\d].*)?\.json$", name):
            return DependencyFileType.COMPOSER_JSON

        if re.search(r"^pom(?:[-_.\s\(\)\d].*)?\.xml$", name):
            return DependencyFileType.MAVEN_POM

        # Step 3 & 4: Extension & Content Inspection
        if path.exists() and path.is_file():
            content_type = cls._inspect_content(path)
            if content_type != DependencyFileType.UNKNOWN:
                return content_type

        return DependencyFileType.UNKNOWN

    @classmethod
    def _inspect_content(cls, path: Path) -> DependencyFileType:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(8192)
        except Exception:
            return DependencyFileType.UNKNOWN

        if not content.strip():
            return DependencyFileType.UNKNOWN

        # 1. JSON Content Check
        if content.strip().startswith("{"):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    if "lockfileVersion" in data:
                        return DependencyFileType.NPM_LOCK
                    if "dependencies" in data or "devDependencies" in data or "peerDependencies" in data:
                        return DependencyFileType.PACKAGE_JSON
                    if "packages" in data and "require" in data:
                        return DependencyFileType.COMPOSER_LOCK
                    if "require" in data or "require-dev" in data:
                        return DependencyFileType.COMPOSER_JSON
            except Exception:
                pass

        # 2. XML Content Check
        if content.strip().startswith("<") or "<project" in content:
            if "<project" in content and ("<dependencies>" in content or "<xmlns" in content):
                return DependencyFileType.MAVEN_POM

        # 3. Python Requirements Line Check
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
        requirements_indicators = 0
        for line in lines:
            if re.search(r"^(?:-r|-c|-i|-f|--extra-index-url|--find-links)\s", line):
                requirements_indicators += 2
            elif re.search(r"^[a-zA-Z0-9_\-\.\[\]]+(?:==|>=|<=|~=|!=|<|>|===|@)\s*[a-zA-Z0-9_\-\.\*]+", line):
                requirements_indicators += 1
            elif re.search(r"^[a-zA-Z0-9_\-\.\[\]]+$", line) and " " not in line:
                requirements_indicators += 1

        if len(lines) > 0 and (requirements_indicators / len(lines)) >= 0.4:
            return DependencyFileType.PYTHON_REQUIREMENTS

        # 4. Cargo / TOML Check
        if "[package]" in content or "[[package]]" in content:
            if "[[package]]" in content and "version =" in content:
                return DependencyFileType.CARGO_LOCK
            if "[package]" in content and "name =" in content:
                return DependencyFileType.CARGO_TOML

        # 5. Go Mod / Sum Check
        if "module " in content and ("go 1." in content or "require (" in content):
            return DependencyFileType.GO_MOD

        # 6. Gemfile Check
        if "source 'https://rubygems.org'" in content or "gem " in content or "GEM\n" in content:
            if "GEM\n" in content or "remote: https://rubygems.org" in content:
                return DependencyFileType.GEMFILE_LOCK
            return DependencyFileType.GEMFILE

        return DependencyFileType.UNKNOWN
