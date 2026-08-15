"""
PULSE Web Technology Capability Registry.

Centralizes all correlation eligibility decisions into a Single Source of Truth.
Every code path (UI, correlation service, reports, exports) MUST use
evaluate_correlation_eligibility() — never inspect correlation_supported or
resolve_technology() independently.

Architecture:
    Catalog     = what the technology is (identity/mapping database)
    Capability  = what can be done with it (provider coverage)
    Eligibility = what PULSE can actually do in this scan (decision/result)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

from pulse.ecosystems.package_identity import PackageIdentity, resolve_technology_package

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CorrelationEligibilityStatus(str, Enum):
    """Mutually exclusive final eligibility status for a detected technology."""
    CORRELATABLE = "Correlatable"
    PARTIALLY_CORRELATABLE = "Partial"
    VERSION_REQUIRED = "Version Required"
    CORRELATION_UNAVAILABLE = "Correlation Unavailable"
    INTELLIGENCE_UNAVAILABLE = "Intel N/A"
    DETECTION_ONLY = "Detection Only"
    CONFIDENCE_TOO_LOW = "Low Confidence"
    RESOLUTION_FAILED = "Resolution Failed"


# ---------------------------------------------------------------------------
# Provider Capability
# ---------------------------------------------------------------------------

@dataclass
class ProviderCapability:
    """Describes whether a specific vulnerability intelligence provider can
    correlate a given technology identity."""
    provider: str               # "OSV", "NVD", "EPSS", "KEV"
    supported: bool
    ecosystem: Optional[str] = None
    package: Optional[str] = None
    cpe_vendor: Optional[str] = None
    cpe_product: Optional[str] = None


# ---------------------------------------------------------------------------
# Correlation Eligibility (the result object)
# ---------------------------------------------------------------------------

@dataclass
class CorrelationEligibility:
    """Immutable result of evaluate_correlation_eligibility().

    Every downstream consumer (UI, service, report, export) reads this object
    instead of independently deciding eligibility.
    """
    status: CorrelationEligibilityStatus

    technology_id: str              # signature_id or lowercase name
    technology_name: str            # display / raw name

    catalog_key: Optional[str] = None

    package_identity: Optional[PackageIdentity] = None
    package_name: Optional[str] = None
    ecosystem: Optional[str] = None

    cpe_vendor: Optional[str] = None
    cpe_product: Optional[str] = None

    reason: str = ""

    lookup_strategy: Optional[str] = None   # "osv" / "nvd" / "both"
    coverage: Optional[str] = None          # "full" / "partial" / "experimental"

    version_required: bool = False
    version_available: bool = False

    confidence: float = 0.0

    intelligence_sources: List[str] = field(default_factory=list)

    @property
    def is_eligible(self) -> bool:
        """True when correlation should proceed."""
        return self.status in (
            CorrelationEligibilityStatus.CORRELATABLE,
            CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE,
        )


# ---------------------------------------------------------------------------
# Confidence threshold (mirrors confidence_correlation.py)
# ---------------------------------------------------------------------------

CORRELATION_CONFIDENCE_THRESHOLD = 40


# ---------------------------------------------------------------------------
# Identity Resolution Helpers
# ---------------------------------------------------------------------------

def _resolve_via_catalog(tech_name: str) -> Optional[dict]:
    """Look up a technology in TECHNOLOGY_CATALOG using name and aliases."""
    from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
    cleaned = tech_name.strip().lower()
    for key, info in TECHNOLOGY_CATALOG.items():
        if cleaned == key.lower():
            return {"key": key, **info}
        if cleaned in [a.lower() for a in info.get("aliases", [])]:
            return {"key": key, **info}
    return None


def _resolve_via_fingerprint(tech) -> dict:
    """Extract package identity directly from the TechnologyFingerprint fields
    that were set by the signature or declarative engine."""
    result: Dict[str, Optional[str]] = {
        "ecosystem": None,
        "package": None,
        "cpe_vendor": None,
        "cpe_product": None,
    }
    # Ecosystem & package from signature fields
    if getattr(tech, "ecosystem", None):
        result["ecosystem"] = tech.ecosystem
        result["package"] = tech.name.lower()

    # CPE candidates from the fingerprint itself
    cpe_cands = getattr(tech, "cpe_candidates", [])
    for cand in cpe_cands:
        cpe_str = cand.cpe if hasattr(cand, "cpe") else str(cand)
        parts = cpe_str.split(":")
        if len(parts) >= 5:
            result["cpe_vendor"] = parts[3]
            result["cpe_product"] = parts[4]
            break

    return result


def _determine_provider_capabilities(
    ecosystem: Optional[str],
    package: Optional[str],
    cpe_vendor: Optional[str],
    cpe_product: Optional[str],
) -> List[ProviderCapability]:
    """Build the list of provider capabilities from resolved identity."""
    caps: List[ProviderCapability] = []

    # OSV — requires ecosystem + package
    if ecosystem and package:
        caps.append(ProviderCapability(
            provider="OSV",
            supported=True,
            ecosystem=ecosystem,
            package=package,
        ))

    # NVD — requires CPE vendor + product
    if cpe_vendor and cpe_product:
        caps.append(ProviderCapability(
            provider="NVD",
            supported=True,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
        ))

    # EPSS / KEV are downstream enrichments; they are available if primary providers are present
    if caps:
        caps.append(ProviderCapability(provider="EPSS", supported=True))
        caps.append(ProviderCapability(provider="KEV", supported=True))

    return caps


def _lookup_strategy_from_caps(caps: List[ProviderCapability]) -> Optional[str]:
    """Derive the lookup_strategy string from provider capabilities."""
    has_osv = any(c.provider == "OSV" and c.supported for c in caps)
    has_nvd = any(c.provider == "NVD" and c.supported for c in caps)
    if has_osv and has_nvd:
        return "both"
    if has_osv:
        return "osv"
    if has_nvd:
        return "nvd"
    return None


# ---------------------------------------------------------------------------
# Main Eligibility Evaluator
# ---------------------------------------------------------------------------

def evaluate_correlation_eligibility(tech) -> CorrelationEligibility:
    """Determine the correlation eligibility of a detected technology.

    Resolution sequence:
        1. Validate fingerprint
        2. Explicit Detection-Only check
        3. Identity Resolution (Catalog -> Fingerprint -> Package Resolver -> CPE)
        4. Confidence Gate
        5. Provider Capabilities & Strategy
        6. Version Check & Status Determination
    """
    # Step 1 — Validate fingerprint
    tech_name = getattr(tech, "name", None)
    tech_id = getattr(tech, "signature_id", "") or (tech_name or "").lower()
    if not tech_name:
        return CorrelationEligibility(
            status=CorrelationEligibilityStatus.RESOLUTION_FAILED,
            technology_id=tech_id or "unknown",
            technology_name="unknown",
            reason="Invalid technology fingerprint (missing name)",
        )

    # Step 2 — Explicit Detection-Only Check
    correlation_flag = getattr(tech, "correlation_supported", True)
    if not correlation_flag:
        return CorrelationEligibility(
            status=CorrelationEligibilityStatus.DETECTION_ONLY,
            technology_id=tech_id,
            technology_name=tech_name,
            reason="Technology signature explicitly marked as detection-only",
        )

    # Step 3 — Multi-source Identity Resolution
    catalog_key: Optional[str] = None
    package_name: Optional[str] = None
    ecosystem: Optional[str] = None
    cpe_vendor: Optional[str] = None
    cpe_product: Optional[str] = None
    coverage: Optional[str] = None
    display_name = tech_name

    # 3a. Catalog lookup
    catalog_entry = _resolve_via_catalog(tech_name)
    if catalog_entry:
        catalog_key = catalog_entry["key"]
        package_name = catalog_entry.get("package")
        ecosystem = catalog_entry.get("ecosystem")
        coverage = catalog_entry.get("coverage")
        display_name = catalog_entry.get("display_name", tech_name)

        cpe_raw = catalog_entry.get("cpe", "")
        if cpe_raw:
            parts = cpe_raw.split(":")
            if len(parts) >= 5:
                cpe_vendor = parts[3]
                cpe_product = parts[4]

    # 3b. Fingerprint-level identity
    fp_identity = _resolve_via_fingerprint(tech)
    if not ecosystem and fp_identity.get("ecosystem"):
        ecosystem = fp_identity["ecosystem"]
    if not package_name and fp_identity.get("package"):
        package_name = fp_identity["package"]
    if not cpe_vendor and fp_identity.get("cpe_vendor"):
        cpe_vendor = fp_identity["cpe_vendor"]
    if not cpe_product and fp_identity.get("cpe_product"):
        cpe_product = fp_identity["cpe_product"]

    # 3c. Canonical Package Resolver fallback
    pkg_identity = resolve_technology_package(tech_name, getattr(tech, "version", None), tech)
    if pkg_identity:
        if not package_name:
            package_name = pkg_identity.name
        if not ecosystem:
            ecosystem = pkg_identity.ecosystem

    has_package_identity = bool(ecosystem and package_name)
    has_cpe_identity = bool(cpe_vendor and cpe_product)

    # Step 4 — Check whether any identity was resolved
    if not has_package_identity and not has_cpe_identity:
        return CorrelationEligibility(
            status=CorrelationEligibilityStatus.RESOLUTION_FAILED,
            technology_id=tech_id,
            technology_name=display_name,
            catalog_key=catalog_key,
            package_identity=pkg_identity,
            reason="No valid package ecosystem or CPE identity could be resolved",
            confidence=getattr(tech, "confidence", 0),
        )

    # Step 5 — Confidence gate
    confidence = getattr(tech, "confidence", 0)
    if confidence < CORRELATION_CONFIDENCE_THRESHOLD:
        return CorrelationEligibility(
            status=CorrelationEligibilityStatus.CONFIDENCE_TOO_LOW,
            technology_id=tech_id,
            technology_name=display_name,
            catalog_key=catalog_key,
            package_identity=pkg_identity,
            package_name=package_name,
            ecosystem=ecosystem,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
            reason=f"Detection confidence {confidence} is below threshold ({CORRELATION_CONFIDENCE_THRESHOLD})",
            confidence=confidence,
        )

    # Step 6 — Version Check & Provider Coverage
    version = getattr(tech, "version", None)
    version_available = bool(version and str(version).strip() and str(version).strip().lower() != "unknown")

    caps = _determine_provider_capabilities(ecosystem, package_name, cpe_vendor, cpe_product)
    intel_sources = [c.provider for c in caps if c.supported]
    lookup_strategy = _lookup_strategy_from_caps(caps)

    if not caps:
        return CorrelationEligibility(
            status=CorrelationEligibilityStatus.INTELLIGENCE_UNAVAILABLE,
            technology_id=tech_id,
            technology_name=display_name,
            catalog_key=catalog_key,
            package_identity=pkg_identity,
            package_name=package_name,
            ecosystem=ecosystem,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
            reason="No vulnerability intelligence provider supports the resolved identity",
            confidence=confidence,
            version_available=version_available,
        )

    # Determine final status
    primary_providers = [c for c in caps if c.provider in ("OSV", "NVD")]
    has_full_coverage = len(primary_providers) >= 2
    is_partial_coverage = coverage == "partial" or len(primary_providers) == 1

    if has_full_coverage and coverage != "partial":
        status = CorrelationEligibilityStatus.CORRELATABLE
    elif is_partial_coverage:
        status = CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE
    else:
        status = CorrelationEligibilityStatus.CORRELATABLE

    # Check version requirement
    needs_version = lookup_strategy in ("osv", "both")
    if needs_version and not version_available:
        status = CorrelationEligibilityStatus.VERSION_REQUIRED
        reason = "Version required for vulnerability correlation"
    else:
        reason = f"{status.value}: {len(intel_sources)} intelligence sources available"

    return CorrelationEligibility(
        status=status,
        technology_id=tech_id,
        technology_name=display_name,
        catalog_key=catalog_key,
        package_identity=pkg_identity,
        package_name=package_name,
        ecosystem=ecosystem,
        cpe_vendor=cpe_vendor,
        cpe_product=cpe_product,
        reason=reason,
        lookup_strategy=lookup_strategy,
        coverage=coverage,
        version_required=needs_version,
        version_available=version_available,
        confidence=confidence,
        intelligence_sources=intel_sources,
    )


# ---------------------------------------------------------------------------
# Batch Evaluation Helper
# ---------------------------------------------------------------------------

def evaluate_all_eligibilities(technologies: list) -> Dict[str, CorrelationEligibility]:
    """Evaluate eligibility for a list of TechnologyFingerprints.

    Returns a dict keyed by technology_id for deterministic downstream consumption.
    """
    result: Dict[str, CorrelationEligibility] = {}
    for tech in technologies:
        elig = evaluate_correlation_eligibility(tech)
        result[elig.technology_id] = elig
    return result


# ---------------------------------------------------------------------------
# Diagnostic Validator
# ---------------------------------------------------------------------------

def validate_technology_capabilities() -> List[str]:
    """Inspect ALL registered technology signatures and validate that
    correlation claims are backed by at least one usable provider."""
    from pulse.website.signatures import SignatureRegistry

    diagnostics: List[str] = []
    signatures = SignatureRegistry.load()

    for sig in signatures:
        if not sig.correlation_supported:
            continue

        mock = _MockFingerprint(
            name=sig.name,
            signature_id=sig.signature_id,
            correlation_supported=True,
            ecosystem=sig.ecosystem,
            cpe_candidates=sig.get_cpe_candidates(None) if sig.provides_cpe_candidates else [],
            confidence=100,
            version="1.0.0",
        )
        elig = evaluate_correlation_eligibility(mock)

        if elig.status in (CorrelationEligibilityStatus.RESOLUTION_FAILED, CorrelationEligibilityStatus.CORRELATION_UNAVAILABLE):
            diagnostics.append(
                f"\u2717 {sig.name} (sig:{sig.signature_id}) — marked correlatable but "
                f"no usable provider: {elig.reason}"
            )
        elif elig.status == CorrelationEligibilityStatus.INTELLIGENCE_UNAVAILABLE:
            diagnostics.append(
                f"\u26a0 {sig.name} (sig:{sig.signature_id}) — intelligence unavailable: "
                f"{elig.reason}"
            )
        elif elig.status == CorrelationEligibilityStatus.PARTIALLY_CORRELATABLE:
            diagnostics.append(
                f"\u2713 {sig.name} (sig:{sig.signature_id}) — {elig.status.value}"
            )
        else:
            diagnostics.append(
                f"\u2713 {sig.name} (sig:{sig.signature_id}) — {elig.status.value}"
            )

    return diagnostics


class _MockFingerprint:
    """Lightweight stand-in for TechnologyFingerprint used by the validator."""

    def __init__(self, *, name, signature_id, correlation_supported,
                 ecosystem, cpe_candidates, confidence, version):
        self.name = name
        self.signature_id = signature_id
        self.correlation_supported = correlation_supported
        self.ecosystem = ecosystem
        self.cpe_candidates = cpe_candidates
        self.confidence = confidence
        self.version = version
