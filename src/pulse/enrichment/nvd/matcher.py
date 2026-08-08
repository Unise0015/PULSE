import logging
from typing import Optional, Tuple, List, Dict, Any
from pulse.domain.version import GenericComparator
from pulse.enrichment.nvd.models import VersionMatchType

logger = logging.getLogger(__name__)


class NVDVersionMatcher:
    """Determines whether a detected version falls within NVD CPE affected ranges.
    
    Parses NVD v2 API 'configurations' blocks containing CPE match criteria
    with versionStartIncluding, versionEndExcluding, etc.
    """

    def __init__(self):
        self.comparator = GenericComparator()

    def match_version(
        self,
        detected_version: Optional[str],
        cve_data: Dict[str, Any],
        target_vendor: str,
        target_product: str
    ) -> Tuple[VersionMatchType, int]:
        """Check if detected_version is affected according to NVD CPE configurations.
        
        Returns (VersionMatchType, confidence_score).
        """
        if not detected_version:
            return (VersionMatchType.UNKNOWN_VERSION, 40)

        configurations = cve_data.get("configurations", [])
        if not configurations:
            # No configuration data — treat as partial match (CPE matched but no version ranges)
            return (VersionMatchType.PARTIAL, 70)

        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                match_result = self._check_node(
                    node, detected_version, target_vendor, target_product
                )
                if match_result is not None:
                    return match_result

        # Went through all configurations, no match found
        return (VersionMatchType.PARTIAL, 0)

    def _check_node(
        self,
        node: Dict[str, Any],
        detected_version: str,
        target_vendor: str,
        target_product: str
    ) -> Optional[Tuple[VersionMatchType, int]]:
        """Check a single configuration node for version matches."""
        cpe_matches = node.get("cpeMatch", [])

        for cpe_match in cpe_matches:
            if not cpe_match.get("vulnerable", False):
                continue

            criteria = cpe_match.get("criteria", "")
            # Parse CPE 2.3 string: cpe:2.3:a:vendor:product:version:...
            parts = criteria.split(":")
            if len(parts) < 6:
                continue

            cpe_vendor = parts[3].lower()
            cpe_product = parts[4].lower()

            # Check if this CPE matches our target vendor/product
            if cpe_vendor != target_vendor.lower() or cpe_product != target_product.lower():
                continue

            cpe_version = parts[5] if len(parts) > 5 else "*"

            # Case 1: Version range constraints
            version_start_incl = cpe_match.get("versionStartIncluding")
            version_start_excl = cpe_match.get("versionStartExcluding")
            version_end_incl = cpe_match.get("versionEndIncluding")
            version_end_excl = cpe_match.get("versionEndExcluding")

            has_range = any([
                version_start_incl, version_start_excl,
                version_end_incl, version_end_excl
            ])

            if has_range:
                if self._version_in_range(
                    detected_version,
                    version_start_incl, version_start_excl,
                    version_end_incl, version_end_excl
                ):
                    return (VersionMatchType.RANGE, 90)
                continue

            # Case 2: Exact version in CPE string
            if cpe_version != "*" and cpe_version != "-":
                if self._versions_equal(detected_version, cpe_version):
                    return (VersionMatchType.EXACT, 100)
                continue

            # Case 3: Wildcard version (all versions vulnerable)
            if cpe_version == "*":
                return (VersionMatchType.PARTIAL, 70)

        # Check nested children nodes (OR/AND logic)
        children = node.get("children", [])
        for child in children:
            result = self._check_node(child, detected_version, target_vendor, target_product)
            if result is not None:
                return result

        return None

    def _version_in_range(
        self,
        detected: str,
        start_incl: Optional[str],
        start_excl: Optional[str],
        end_incl: Optional[str],
        end_excl: Optional[str]
    ) -> bool:
        """Check if detected version is within a version range."""
        try:
            if start_incl and not self.comparator.compare(detected, ">=", start_incl):
                return False
            if start_excl and not self.comparator.compare(detected, ">", start_excl):
                return False
            if end_incl and not self.comparator.compare(detected, "<=", end_incl):
                return False
            if end_excl and not self.comparator.compare(detected, "<", end_excl):
                return False
            return True
        except Exception:
            logger.debug("Version range comparison failed for %s", detected)
            return False

    def _versions_equal(self, v1: str, v2: str) -> bool:
        """Check if two version strings are semantically equal."""
        try:
            return self.comparator.compare(v1, "==", v2)
        except Exception:
            return v1.strip().lower() == v2.strip().lower()
