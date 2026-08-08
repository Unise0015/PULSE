import re
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Tuple
from packaging.version import Version, InvalidVersion

class BranchStatus(Enum):
    SUPPORTED = "Supported"
    EOL = "End-of-Life"
    UNKNOWN = "Unknown"

class RegistryType(Enum):
    PYPI = "PyPI"
    NPM = "npm"
    CRATES = "crates.io"
    RUBYGEMS = "RubyGems"
    PACKAGIST = "Packagist"
    MAVEN = "Maven"
    NUGET = "NuGet"
    UNKNOWN = "Unknown"

@dataclass
class NormalizedAffectedRange:
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    limit: Optional[str] = None

class VersionComparator(ABC):
    @abstractmethod
    def parse(self, version_str: str) -> any:
        """Parse version string into a comparable object."""
        pass

    @abstractmethod
    def compare(self, v1: str, op: str, v2: str) -> bool:
        """Compare two version strings using the specified operator (<, <=, >, >=, ==, !=)."""
        pass

    @abstractmethod
    def is_stable(self, version_str: str) -> bool:
        """Check if the version is a stable (non-prerelease) release."""
        pass


class GenericComparator(VersionComparator):
    """Fallback generic comparator utilizing numeric/alphabetic token tuples."""
    
    def parse(self, v: str) -> Tuple[Tuple[int, ...], bool, Tuple[Tuple[int, str], ...]]:
        v = v.strip()
        if v.lower().startswith("v"):
            v = v[1:]
            
        match = re.match(r'^([0-9]+(?:\.[0-9]+)*)(.*)$', v)
        if not match:
            return ((0, 0, 0, 0, 0), False, ())
            
        prefix, suffix = match.groups()
        num_parts = [int(x) for x in prefix.split(".")]
        padded_num = tuple(num_parts + [0] * (5 - len(num_parts)))
        
        tokens = []
        for token in re.findall(r'[0-9]+|[a-zA-Z]+', suffix):
            if token.isdigit():
                tokens.append((0, int(token)))
            else:
                tokens.append((1, token.lower()))
                
        is_stable = True
        prerelease_keywords = {"alpha", "beta", "rc", "preview", "pre", "dev", "milestone", "m", "b", "a"}
        if any(tok[1] in prerelease_keywords for tok in tokens if tok[0] == 1):
            is_stable = False
        elif suffix and not any(tok[1] in {"release", "final", "ga", "stable"} for tok in tokens if tok[0] == 1):
            is_stable = False
            
        return (padded_num, is_stable, tuple(tokens))

    def compare(self, v1: str, op: str, v2: str) -> bool:
        try:
            val1 = self.parse(v1)
            val2 = self.parse(v2)
        except Exception:
            return False
            
        # In this tuple representation, stable (True) > prerelease (False)
        # However, numeric is compared first. E.g. ((1, 0, 0), True, ()) vs ((1, 0, 0), False, ...)
        # It handles comparisons beautifully.
        if op == ">=": return val1 >= val2
        if op == "<=": return val1 <= val2
        if op == ">": return val1 > val2
        if op == "<": return val1 < val2
        if op == "==": return val1 == val2
        if op == "!=": return val1 != val2
        return False

    def is_stable(self, version_str: str) -> bool:
        try:
            _, is_stable, _ = self.parse(version_str)
            return is_stable
        except Exception:
            return False


class PyPIComparator(VersionComparator):
    """PyPI and fallback Maven/NuGet/RubyGems comparator using packaging.version."""
    
    def __init__(self):
        self.generic = GenericComparator()

    def _normalize(self, v: str) -> str:
        v = v.strip()
        # Strip common Maven/NuGet suffixes to align with PEP-440
        # E.g. 1.0.0.RELEASE -> 1.0.0, 1.0.0.Final -> 1.0.0
        # NuGet 1.0.0-preview.1 -> 1.0.0rc1 or similar, or leave it as is if PEP-440 parses it.
        v_lower = v.lower()
        for suffix in [".release", ".final", ".ga", "-release", "-final", "-ga"]:
            if v_lower.endswith(suffix):
                v = v[:-len(suffix)]
                v_lower = v.lower()
        return v

    def parse(self, v: str) -> Version:
        norm = self._normalize(v)
        return Version(norm)

    def compare(self, v1: str, op: str, v2: str) -> bool:
        try:
            val1 = self.parse(v1)
            val2 = self.parse(v2)
        except InvalidVersion:
            # Fallback to Generic Comparator if invalid PEP-440 version string
            return self.generic.compare(v1, op, v2)
            
        if op == ">=": return val1 >= val2
        if op == "<=": return val1 <= val2
        if op == ">": return val1 > val2
        if op == "<": return val1 < val2
        if op == "==": return val1 == val2
        if op == "!=": return val1 != val2
        return False

    def is_stable(self, version_str: str) -> bool:
        try:
            val = self.parse(version_str)
            return not val.is_prerelease
        except InvalidVersion:
            return self.generic.is_stable(version_str)


class NpmComparator(VersionComparator):
    """Npm comparator implementing robust SemVer rules."""
    
    def __init__(self):
        self.generic = GenericComparator()

    def parse(self, v: str) -> Tuple[Tuple[int, ...], bool, Tuple[Tuple[int, any], ...]]:
        v = v.strip()
        if v.lower().startswith("v"):
            v = v[1:]
            
        # Split prerelease and build metadata
        # E.g. 1.2.3-beta.1+build.123
        if "+" in v:
            v, _ = v.split("+", 1)
        
        prerelease = ""
        if "-" in v:
            v, prerelease = v.split("-", 1)
            
        parts = v.split(".")
        major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        
        is_stable = (prerelease == "")
        
        prerelease_tokens = []
        if prerelease:
            for token in prerelease.split("."):
                if token.isdigit():
                    prerelease_tokens.append((0, int(token)))
                else:
                    prerelease_tokens.append((1, token.lower()))
                    
        return ((major, minor, patch), is_stable, tuple(prerelease_tokens))

    def compare(self, v1: str, op: str, v2: str) -> bool:
        try:
            val1 = self.parse(v1)
            val2 = self.parse(v2)
        except Exception:
            return self.generic.compare(v1, op, v2)
            
        if op == ">=": return val1 >= val2
        if op == "<=": return val1 <= val2
        if op == ">": return val1 > val2
        if op == "<": return val1 < val2
        if op == "==": return val1 == val2
        if op == "!=": return val1 != val2
        return False

    def is_stable(self, version_str: str) -> bool:
        try:
            _, is_stable, _ = self.parse(version_str)
            return is_stable
        except Exception:
            return False


def get_comparator(ecosystem: str) -> VersionComparator:
    eco = ecosystem.lower()
    if eco in ("pypi", "python"):
        return PyPIComparator()
    if eco in ("npm", "node", "node.js"):
        return NpmComparator()
    if eco in ("maven", "java"):
        return PyPIComparator()  # Reuse PyPIComparator with normalization for Maven
    if eco in ("nuget", ".net", "dotnet"):
        return PyPIComparator()  # Reuse PyPIComparator with normalization for NuGet
    if eco in ("ruby", "rubygems"):
        return PyPIComparator()  # Reuse PyPIComparator with normalization for RubyGems
    if eco in ("composer", "php", "packagist"):
        return PyPIComparator()
    return GenericComparator()
