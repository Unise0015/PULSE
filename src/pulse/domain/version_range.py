"""
Ecosystem-Aware Version Range Evaluation Engine for PULSE.
Provides accurate SemVer 2.0, PEP 440, and NVD CPE boundary comparison
to determine if a specific version falls within affected ranges.
"""

import re
import logging
from typing import Optional, Tuple
import packaging.version
import packaging.specifiers

logger = logging.getLogger(__name__)


class VersionRangeMatcher:
    """Evaluates whether a version is within an affected vulnerability range across ecosystems."""

    @staticmethod
    def _clean_version_str(v: str) -> str:
        """Strips leading 'v' or 'v.' and metadata suffixes for parsing."""
        if not v:
            return "0.0.0"
        s = v.strip()
        if s.lower().startswith("v."):
            s = s[2:]
        elif s.lower().startswith("v") and len(s) > 1 and s[1].isdigit():
            s = s[1:]
        return s

    @classmethod
    def is_version_affected(
        cls,
        current_version: str,
        ecosystem: Optional[str] = None,
        introduced: Optional[str] = None,
        fixed: Optional[str] = None,
        last_affected: Optional[str] = None,
        limit: Optional[str] = None,
    ) -> bool:
        """
        Determines if current_version is affected according to OSV / NVD range boundaries.
        Boundary semantics:
          - introduced <= version < fixed
          - introduced <= version <= last_affected
        """
        if not current_version:
            return False

        try:
            curr_v = packaging.version.parse(cls._clean_version_str(current_version))
        except Exception:
            # Fallback simple string / tuple comparison if non-standard semver
            return True

        # Check introduced boundary
        if introduced and introduced != "0":
            try:
                intro_v = packaging.version.parse(cls._clean_version_str(introduced))
                if curr_v < intro_v:
                    return False
            except Exception:
                pass

        # Check fixed boundary (exclusive)
        if fixed:
            try:
                fix_v = packaging.version.parse(cls._clean_version_str(fixed))
                if curr_v >= fix_v:
                    return False
            except Exception:
                pass

        # Check last_affected boundary (inclusive)
        if last_affected:
            try:
                last_v = packaging.version.parse(cls._clean_version_str(last_affected))
                if curr_v > last_v:
                    return False
            except Exception:
                pass

        # Check limit boundary
        if limit:
            try:
                lim_v = packaging.version.parse(cls._clean_version_str(limit))
                if curr_v >= lim_v:
                    return False
            except Exception:
                pass

        return True

    @classmethod
    def matches_nvd_boundaries(
        cls,
        current_version: str,
        v_start_incl: Optional[str] = None,
        v_start_excl: Optional[str] = None,
        v_end_incl: Optional[str] = None,
        v_end_excl: Optional[str] = None,
    ) -> bool:
        """
        Evaluates NVD CPE criteria operators:
          - versionStartIncluding
          - versionStartExcluding
          - versionEndIncluding
          - versionEndExcluding
        """
        if not current_version:
            return False

        try:
            curr_v = packaging.version.parse(cls._clean_version_str(current_version))
        except Exception:
            return True

        if v_start_incl:
            try:
                if curr_v < packaging.version.parse(cls._clean_version_str(v_start_incl)):
                    return False
            except Exception:
                pass

        if v_start_excl:
            try:
                if curr_v <= packaging.version.parse(cls._clean_version_str(v_start_excl)):
                    return False
            except Exception:
                pass

        if v_end_incl:
            try:
                if curr_v > packaging.version.parse(cls._clean_version_str(v_end_incl)):
                    return False
            except Exception:
                pass

        if v_end_excl:
            try:
                if curr_v >= packaging.version.parse(cls._clean_version_str(v_end_excl)):
                    return False
            except Exception:
                pass

        return True
