import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
import httpx
import logging

from pulse.ecosystems.registry import PluginRegistry
from pulse.ecosystems.base import EcosystemPlugin, ECOSYSTEM_REGISTRY_MAP
from pulse.ecosystems.ecosystems_client import EcosystemsClient
from pulse.ecosystems.package_identity import get_known_identity

logger = logging.getLogger(__name__)

# Map ecosyste.ms internal ecosystem names to PULSE ecosystem/provider names
ECOSYSTEMS_MS_TO_PULSE = {
    "npm": "Node.js",
    "pypi": "Python",
    "cargo": "Rust",
    "go": "Go",
    "rubygems": "Ruby",
    "packagist": "Composer",
    "nuget": "NuGet",
    "maven": "Maven",
    "swift": "Swift",
    "pub": "Dart",
    "hex": "Hex",
    "cran": "CRAN",
    "clojars": "Clojars",
    "hackage": "Hackage",
    "cpan": "CPAN",
    "conan": "Conan",
    "terraform": "Terraform",
    "helm": "Helm",
    "alpine": "Alpine",
    "debian": "Debian"
}

@dataclass
class PackageCandidate:
    ecosystem: str
    registry_name: str
    package_name: str
    requested_version: Optional[str]
    package_exists: bool
    version_exists: bool
    confidence: int
    source: str
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    latest_version: Optional[str] = None
    ecosystem_identity_confidence: int = 0
    reason: str = ""
    provider: Optional[EcosystemPlugin] = None

@dataclass
class PackageResolutionResult:
    package_name: str
    normalized_package_name: str
    requested_version: Optional[str]
    
    ecosystem: Optional[str] = None
    registry_name: Optional[str] = None
    provider: Optional[EcosystemPlugin] = None
    
    confidence: int = 0
    package_exists: bool = False
    version_exists: bool = False
    version_verified: bool = False
    
    resolution_reason: str = ""
    detection_source: str = ""
    requires_user_selection: bool = False
    
    candidates: List[PackageCandidate] = field(default_factory=list)
    alternative_candidates: List[PackageCandidate] = field(default_factory=list)
    package_metadata: Dict[str, Any] = field(default_factory=dict)
    
    network_error: bool = False


class PackageResolutionService:
    def __init__(self):
        self.ecosystems_client = EcosystemsClient()
        self.providers = PluginRegistry.load()
        self._provider_map = {p.manifest.name: p for p in self.providers}

    async def _check_native_provider(self, client: httpx.AsyncClient, provider: EcosystemPlugin, package_name: str, version: Optional[str]) -> Optional[PackageCandidate]:
        try:
            res = await provider.validate_registry_async(client, package_name, version)
            if res and res.package_exists:
                return PackageCandidate(
                    ecosystem=provider.manifest.name,
                    registry_name=ECOSYSTEM_REGISTRY_MAP.get(provider.manifest.name, provider.manifest.ecosystem or provider.manifest.name),
                    package_name=package_name,
                    requested_version=version,
                    package_exists=True,
                    version_exists=res.version_exists,
                    confidence=0,  # Will be scored later
                    source="native_registry",
                    latest_version=res.latest_available_version,
                    provider=provider
                )
        except Exception as e:
            logger.debug(f"Native provider check failed for {provider.manifest.name}: {e}")
        return None

    def _score_candidate(self, candidate: PackageCandidate, local_eco: str, is_ecosystems_ms: bool) -> PackageCandidate:
        score = 0
        reasons = []

        if local_eco and local_eco.lower() == candidate.ecosystem.lower():
            score += 25
            reasons.append("Known local identity mapping")

        # Basic exact match points
        score += 20
        reasons.append("Exact name match")

        if candidate.requested_version:
            if candidate.version_exists:
                score += 30
                reasons.append("Exact version verified")
            else:
                score -= 25
                reasons.append("Requested version not found")
        else:
            # If no version requested but package exists
            score += 20
            
        if is_ecosystems_ms:
            score += 15
            reasons.append("ecosyste.ms confirmation")
        else:
            score += 15
            reasons.append("Native registry confirmation")

        if candidate.description or candidate.repository_url:
            score += 10
            reasons.append("Rich metadata present")

        # Clamp score 0-100
        candidate.confidence = max(0, min(100, score))
        candidate.reason = ", ".join(reasons)
        return candidate

    async def resolve(self, package_name: str, version: Optional[str] = None) -> PackageResolutionResult:
        result = PackageResolutionResult(
            package_name=package_name,
            normalized_package_name=package_name.lower(),
            requested_version=version
        )

        local_eco, local_reg = get_known_identity(package_name)

        candidates: List[PackageCandidate] = []
        
        # 1. ecosyste.ms search
        ecosystems_pkgs = await self.ecosystems_client.search_packages(package_name)
        if not ecosystems_pkgs:
            # Maybe network error if returned empty but not 404? We assume 404/empty.
            # Client returns empty list on error too, but we can check if it's disabled.
            pass
            
        for pkg in ecosystems_pkgs:
            if pkg.get("name", "").lower() == package_name.lower():
                eco_key = pkg.get("registry", {}).get("ecosystem", "")
                pulse_eco = ECOSYSTEMS_MS_TO_PULSE.get(eco_key)
                
                # If we don't have a mapping, we can still show it as a candidate if we want,
                # but we prefer mapping it to a known pulse provider.
                if pulse_eco and pulse_eco in self._provider_map:
                    provider = self._provider_map[pulse_eco]
                    
                    version_exists = False
                    if version:
                        ver_data = await self.ecosystems_client.get_package_version(pkg.get("registry", {}).get("name", ""), package_name, version)
                        version_exists = bool(ver_data)
                    
                    c = PackageCandidate(
                        ecosystem=pulse_eco,
                        registry_name=ECOSYSTEM_REGISTRY_MAP.get(pulse_eco, pulse_eco),
                        package_name=pkg.get("name"),
                        requested_version=version,
                        package_exists=True,
                        version_exists=version_exists,
                        confidence=0,
                        source="ecosystems_ms",
                        description=pkg.get("description"),
                        homepage=pkg.get("homepage"),
                        repository_url=pkg.get("repository_url"),
                        provider=provider
                    )
                    candidates.append(c)

        # 2. Native Providers (if not already found by ecosyste.ms for that provider)
        found_ecos = {c.ecosystem for c in candidates}
        async with httpx.AsyncClient(timeout=5.0) as client:
            native_tasks = []
            for provider in self.providers:
                if provider.manifest.name not in found_ecos:
                    native_tasks.append(self._check_native_provider(client, provider, package_name, version))
            
            if native_tasks:
                native_results = await asyncio.gather(*native_tasks)
                for nr in native_results:
                    if nr:
                        candidates.append(nr)

        # 3. Score Candidates
        for c in candidates:
            self._score_candidate(c, local_eco, c.source == "ecosystems_ms")

        candidates.sort(key=lambda x: x.confidence, reverse=True)

        # Filter out extremely low confidence unless it's the only one
        good_candidates = [c for c in candidates if c.confidence >= 50]
        if not good_candidates and candidates:
            good_candidates = [candidates[0]]
            
        result.candidates = good_candidates
        
        if not good_candidates:
            result.resolution_reason = "Package not found in any supported ecosystem."
            return result

        best = good_candidates[0]
        
        # Determine auto-resolution
        is_clearly_ahead = True
        if len(good_candidates) > 1:
            second_best = good_candidates[1]
            if best.confidence - second_best.confidence < 15:
                is_clearly_ahead = False
                
        # Also auto-resolve if local identity is strong
        strong_local = (local_eco and local_eco.lower() == best.ecosystem.lower())

        if (best.confidence >= 60 and is_clearly_ahead) or strong_local or len(good_candidates) == 1:
            result.ecosystem = best.ecosystem
            result.registry_name = best.registry_name
            result.provider = best.provider
            result.confidence = best.confidence
            result.package_exists = best.package_exists
            result.version_exists = best.version_exists
            result.version_verified = best.version_exists
            result.detection_source = best.source
            result.resolution_reason = best.reason
            result.requires_user_selection = False
        else:
            result.requires_user_selection = True
            result.alternative_candidates = good_candidates
            result.resolution_reason = "Ambiguous package identity or missing version."

        return result
