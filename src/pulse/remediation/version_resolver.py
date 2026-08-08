from typing import List, Optional, Dict, Set, Tuple
from packaging.version import parse as parse_version, InvalidVersion
from pulse.domain.models import VulnerabilityFinding, VersionMetadata

KNOWN_LTS_BRANCHES: Dict[str, Set[str]] = {
    "django": {"1.11", "2.2", "3.2", "4.2", "5.2"},
    "node": {"14", "16", "18", "20", "22"},
    "nodejs": {"14", "16", "18", "20", "22"},
    "ubuntu": {"18.04", "20.04", "22.04", "24.04"},
    "laravel/framework": {"6.0", "9.0", "10.0", "11.0"},
    "react": {"17.0", "18.0"},
}


class VersionResolver:
    """Discovers versions, separates prereleases, groups release lines, and extracts fix candidates."""

    @staticmethod
    def is_prerelease(version_str: str) -> bool:
        if not version_str:
            return False
        try:
            v = parse_version(version_str)
            return v.is_prerelease or v.is_devrelease
        except InvalidVersion:
            lowered = version_str.lower()
            return any(tag in lowered for tag in ("alpha", "beta", "rc", "dev", "preview", "next"))

    @staticmethod
    def extract_fix_versions(findings: List[VulnerabilityFinding]) -> List[str]:
        fixes: Set[str] = set()
        for f in findings:
            if f.fix_version:
                for chunk in str(f.fix_version).replace(";", ",").split(","):
                    cleaned = chunk.strip().lstrip("=v><~^")
                    if cleaned and not cleaned.lower().startswith("n/a"):
                        fixes.add(cleaned)
        return sorted(list(fixes), key=lambda x: VersionResolver._version_key(x))

    @staticmethod
    def _version_key(version_str: str):
        try:
            return parse_version(version_str)
        except InvalidVersion:
            return parse_version("0.0.0")

    @staticmethod
    def get_major_minor_branch(version_str: str) -> str:
        try:
            v = parse_version(version_str)
            return f"{v.major}.{v.minor}"
        except InvalidVersion:
            parts = version_str.split(".")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}"
            return version_str

    @staticmethod
    def is_lts_branch(package_name: str, version_str: str) -> bool:
        pkg_lower = package_name.lower().strip()
        branch = VersionResolver.get_major_minor_branch(version_str)
        major = str(parse_version(version_str).major) if not VersionResolver.is_prerelease(version_str) else ""

        if pkg_lower in KNOWN_LTS_BRANCHES:
            lts_set = KNOWN_LTS_BRANCHES[pkg_lower]
            return branch in lts_set or major in lts_set
        return False

    @staticmethod
    def get_latest_versions(
        current_version: str,
        fix_versions: List[str],
        version_metadata: Optional[VersionMetadata] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """Returns (latest_stable_version, latest_available_version)."""
        all_candidates: Set[str] = set(fix_versions)
        if version_metadata:
            if version_metadata.latest_stable_version:
                all_candidates.add(version_metadata.latest_stable_version)
            if version_metadata.latest_security_fix:
                all_candidates.add(version_metadata.latest_security_fix)
            if version_metadata.minimum_safe_version:
                all_candidates.add(version_metadata.minimum_safe_version)

        if not all_candidates:
            return None, None

        sorted_all = sorted(list(all_candidates), key=lambda x: VersionResolver._version_key(x), reverse=True)
        latest_available = sorted_all[0] if sorted_all else None

        stables = [v for v in sorted_all if not VersionResolver.is_prerelease(v)]
        latest_stable = stables[0] if stables else latest_available

        return latest_stable, latest_available
