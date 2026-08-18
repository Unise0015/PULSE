"""
Smart Package Disambiguation Engine for PULSE.
Distinguishes between:
  1. EXACT_PACKAGE_MATCH (Active library on npm/PyPI matching requested version)
  2. PURE_COLLISION (Stub/wrapper on npm/PyPI far outside queried version vs Standalone Infrastructure)
  3. DUAL_IDENTITY (Software existing both as active client SDK and standalone server)
"""

import logging
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Any

from pulse.vulnerability.cpe_resolver import KNOWN_VENDOR_LINEAGES

logger = logging.getLogger(__name__)


class DisambiguationType(Enum):
    EXACT_PACKAGE_MATCH = "EXACT_PACKAGE_MATCH"
    PURE_COLLISION = "PURE_COLLISION"
    DUAL_IDENTITY = "DUAL_IDENTITY"
    STANDALONE_SOFTWARE = "STANDALONE_SOFTWARE"


# Wrapper / Stub indicators in registry package descriptions
WRAPPER_INDICATORS = [
    r"\bwrapper\b",
    r"\binstalling and configuring\b",
    r"\btools for\b",
    r"\bunofficial\b",
    r"\bstub\b",
    r"\bexecutable wrapper\b",
    r"\bhelper script\b"
]


@dataclass
class DisambiguationAnalysis:
    classification: DisambiguationType
    confidence: int
    recommended_ecosystem: str
    is_standalone: bool = False
    warning_message: Optional[str] = None
    cpe_candidates: List[str] = field(default_factory=list)


class PackageDisambiguator:
    """Evaluates registry candidate signals against standalone software heuristics."""

    @classmethod
    def evaluate(
        cls,
        package_name: str,
        requested_version: Optional[str],
        candidate_ecosystem: Optional[str],
        candidate_version_exists: bool,
        candidate_description: Optional[str] = None,
        all_published_versions: Optional[List[str]] = None
    ) -> DisambiguationAnalysis:
        """
        Evaluates whether a candidate match is a genuine package or a pure collision / standalone software.
        """
        norm_name = package_name.lower().strip()
        is_known_standalone = norm_name in KNOWN_VENDOR_LINEAGES

        # 1. Exact Version Match in Registry Index -> Legitimate Client / Library
        if candidate_version_exists and candidate_ecosystem:
            return DisambiguationAnalysis(
                classification=DisambiguationType.EXACT_PACKAGE_MATCH,
                confidence=95,
                recommended_ecosystem=candidate_ecosystem,
                is_standalone=False
            )

        # 2. Check for Wrapper / Stub Description
        has_wrapper_desc = False
        if candidate_description:
            for pat in WRAPPER_INDICATORS:
                if re.search(pat, candidate_description, re.IGNORECASE):
                    has_wrapper_desc = True
                    break

        # 3. Check for Version Spectrum Alienation
        # (e.g. queried 1.24.0, but package versions on registry stopped at 1.1.0 in 2014)
        is_version_alien = False
        if requested_version and all_published_versions:
            try:
                # If requested version is not in versions list and highest published is < requested
                if requested_version not in all_published_versions:
                    is_version_alien = True
            except Exception:
                pass

        # 4. Pure Collision Decision (e.g. nginx 1.24.0 on npm)
        if is_known_standalone and (not candidate_version_exists or has_wrapper_desc):
            from pulse.vulnerability.cpe_resolver import CPEResolver
            cpes = CPEResolver.get_cpe_candidates(norm_name, requested_version)
            
            warning = None
            if candidate_ecosystem:
                warning = f"The {candidate_ecosystem} package '{package_name}' is a tool/wrapper that does not contain version {requested_version}. Routing to Standalone / Infrastructure engine (CPE & Linux Distros)."

            return DisambiguationAnalysis(
                classification=DisambiguationType.PURE_COLLISION,
                confidence=95,
                recommended_ecosystem="Standalone Software",
                is_standalone=True,
                warning_message=warning,
                cpe_candidates=cpes
            )

        # 5. Standalone Software Direct Recognition
        if is_known_standalone and not candidate_ecosystem:
            from pulse.vulnerability.cpe_resolver import CPEResolver
            cpes = CPEResolver.get_cpe_candidates(norm_name, requested_version)
            return DisambiguationAnalysis(
                classification=DisambiguationType.STANDALONE_SOFTWARE,
                confidence=90,
                recommended_ecosystem="Standalone Software",
                is_standalone=True,
                cpe_candidates=cpes
            )

        # 6. Default Fallback
        return DisambiguationAnalysis(
            classification=DisambiguationType.DUAL_IDENTITY if is_known_standalone else DisambiguationType.EXACT_PACKAGE_MATCH,
            confidence=60,
            recommended_ecosystem=candidate_ecosystem or "Unknown",
            is_standalone=is_known_standalone
        )
