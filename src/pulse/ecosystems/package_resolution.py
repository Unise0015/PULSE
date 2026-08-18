import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
import httpx
import logging

from pulse.ecosystems.registry import PluginRegistry
from pulse.ecosystems.base import EcosystemPlugin, ECOSYSTEM_REGISTRY_MAP
from pulse.ecosystems.ecosystems_client import EcosystemsClient
from pulse.ecosystems.package_identity import get_known_identity
from pulse.ecosystems.smart_detection import RegistryValidationResult

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

# System/distro-level ecosystems that should be deprioritized
# when an application-level identity hint exists.
SYSTEM_ECOSYSTEMS = {"Alpine", "Debian", "Ubuntu", "RPM", "Arch", "Nix"}

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
    is_standalone: bool = False
    warning_message: Optional[str] = None
    cpe_candidates: List[str] = field(default_factory=list)


class PackageResolutionService:
    """Resolves a package name + version to a PULSE ecosystem provider.
    
    Uses concurrent evidence from:
      1. Local identity hints (data-driven canonical mappings)
      2. ecosyste.ms API (cross-registry metadata)
      3. Native registry APIs (npm, PyPI, crates.io, etc.)
    
    The resolved provider is the SAME provider used for vulnerability scanning,
    preventing any provider/ecosystem mismatch.
    """
    
    def __init__(self):
        self.ecosystems_client = EcosystemsClient()
        self.providers = PluginRegistry.load()
        self._provider_map = {p.manifest.name: p for p in self.providers}

    # ── Real Registry Check Methods (reused from SmartEcosystemDetector) ──

    async def _check_pypi(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            resp = await client.get(f"https://pypi.org/pypi/{name}/json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("info", {}).get("version")
                has_version = True
                if version:
                    releases = data.get("releases", {})
                    clean_ver = version.lstrip("vV ")
                    norm_ver = clean_ver[:-2] if clean_ver.endswith(".0") and clean_ver.count(".") == 2 else clean_ver
                    alt_zero = f"{clean_ver}.0" if clean_ver.count(".") == 1 else clean_ver
                    has_version = (
                        version in releases or
                        clean_ver in releases or
                        norm_ver in releases or
                        alt_zero in releases or
                        f"v{clean_ver}" in releases
                    )
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_npm(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            # npm registry is case-insensitive but prefers lowercase
            resp = await client.get(f"https://registry.npmjs.org/{name.lower()}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("dist-tags", {}).get("latest")
                has_version = True
                if version:
                    clean_ver = version.lstrip("vV ")
                    versions_dict = data.get("versions", {})
                    has_version = (version in versions_dict) or (clean_ver in versions_dict) or (f"v{clean_ver}" in versions_dict)
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_crates(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            resp = await client.get(f"https://crates.io/api/v1/crates/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("crate", {}).get("max_version")
                has_version = True
                if version:
                    clean_ver = version.lstrip("vV ")
                    has_version = any(v.get("num") in (version, clean_ver, f"v{clean_ver}") for v in data.get("versions", []))
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_rubygems(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            resp = await client.get(f"https://rubygems.org/api/v1/gems/{name}.json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("version")
                has_version = True
                if version:
                    v_resp = await client.get(f"https://rubygems.org/api/v1/versions/{name}.json")
                    if v_resp.status_code == 200:
                        has_version = any(v.get("number") == version for v in v_resp.json())
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_packagist(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            if name.lower() == "php":
                return RegistryValidationResult(True, True, "8.4.22", False, 200)
            resp = await client.get(f"https://packagist.org/packages/{name}.json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                versions = data.get("package", {}).get("versions", {})
                latest = None
                for v in versions.keys():
                    if "dev" not in v and "alpha" not in v and "beta" not in v and "rc" not in v:
                        latest = v.lstrip("v")
                        break
                has_version = True
                if version:
                    clean_ver = version.lstrip("vV ")
                    has_version = (version in versions) or (clean_ver in versions) or (f"v{clean_ver}" in versions)
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_nuget(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            resp = await client.get(f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/index.json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                versions = data.get("versions", [])
                latest = versions[-1] if versions else None
                has_version = True
                if version:
                    clean_ver = version.lstrip("vV ")
                    has_version = (version in versions) or (clean_ver in versions) or (f"v{clean_ver}" in versions)
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_maven(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            query = f"g:{name}"
            if ":" in name:
                g, a = name.split(":", 1)
                query = f'g:"{g}" AND a:"{a}"'
            resp = await client.get("https://search.maven.org/solrsearch/select", params={"q": query})
            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                if data.get("response", {}).get("numFound", 0) > 0 and docs:
                    latest = docs[0].get("latestVersion")
                    return RegistryValidationResult(True, True, latest, False, 200)
                return RegistryValidationResult(False, False, None, False, 404)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_go(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            encoded = []
            for char in name:
                if char.isupper():
                    encoded.append(f"!{char.lower()}")
                else:
                    encoded.append(char)
            encoded_name = "".join(encoded)
            resp = await client.get(f"https://proxy.golang.org/{encoded_name}/@v/list")
            if resp.status_code in (404, 410):
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                versions = resp.text.splitlines()
                latest = versions[-1] if versions else None
                has_version = True
                if version:
                    has_version = version in versions or f"v{version}" in versions
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    # ── Provider Check Dispatcher ──

    _REGISTRY_CHECK_MAP = {
        "python": "_check_pypi",
        "node.js": "_check_npm",
        "rust": "_check_crates",
        "go": "_check_go",
        "ruby": "_check_rubygems",
        "composer": "_check_packagist",
        "nuget": "_check_nuget",
        "maven": "_check_maven",
    }

    async def _check_native_provider(self, client: httpx.AsyncClient, provider: EcosystemPlugin, package_name: str, version: Optional[str]) -> Optional[PackageCandidate]:
        """Check a single provider against its native registry."""
        try:
            eco_name = provider.manifest.name.lower()
            
            # Use the real registry check if available for original 9 ecosystems
            check_method_name = self._REGISTRY_CHECK_MAP.get(eco_name)
            if check_method_name:
                check_method = getattr(self, check_method_name)
                res = await check_method(client, package_name, version)
            else:
                # Fall back to the provider's own validate_registry_async
                res = await provider.validate_registry_async(client, package_name, version)
                
            if res is None or not res.package_exists:
                return None
                
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

    def _score_candidate(self, candidate: PackageCandidate, local_eco: Optional[str]) -> PackageCandidate:
        """Score a candidate based on multiple evidence signals."""
        score = 0
        reasons = []

        # Signal 1: Local identity hint match (+25)
        if local_eco and local_eco.lower() == candidate.ecosystem.lower():
            score += 25
            reasons.append("Known identity mapping")

        # Signal 2: Package exists in registry (+20)
        score += 20
        reasons.append("Registry match")

        # Signal 3: Version verification (+30 if exists, -25 if not)
        if candidate.requested_version:
            if candidate.version_exists:
                score += 30
                reasons.append("Version verified")
            else:
                score -= 25
                reasons.append("Version not found")
        else:
            score += 20

        # Signal 4: Source quality (+15)
        if candidate.source == "ecosystems_ms":
            score += 15
            reasons.append("ecosyste.ms confirmed")
        else:
            score += 15
            reasons.append("Native registry confirmed")

        # Signal 5: Rich metadata (+10)
        if candidate.description or candidate.repository_url:
            score += 10
            reasons.append("Rich metadata")

        # Signal 6: System-level ecosystem penalty (-20 when app-level hint exists)
        if local_eco and candidate.ecosystem in SYSTEM_ECOSYSTEMS:
            score -= 20
            reasons.append("System ecosystem deprioritized")

        # Clamp 0-100
        candidate.confidence = max(0, min(100, score))
        candidate.reason = ", ".join(reasons)
        return candidate

    async def resolve(self, package_name: str, version: Optional[str] = None) -> PackageResolutionResult:
        result = PackageResolutionResult(
            package_name=package_name,
            normalized_package_name=package_name.lower(),
            requested_version=version
        )

        from pulse.ecosystems.package_identity import get_canonical_package_info
        canon_name, canon_eco, canon_reg = get_canonical_package_info(package_name)
        search_pkg_name = canon_name if canon_name else package_name
        local_eco, local_reg = (canon_eco, canon_reg) if canon_eco else get_known_identity(package_name)

        candidates: List[PackageCandidate] = []
        
        # ── Evidence Source 1: ecosyste.ms search ──
        ecosystems_pkgs = await self.ecosystems_client.search_packages(search_pkg_name)
            
        for pkg in ecosystems_pkgs:
            if pkg.get("name", "").lower() in (package_name.lower(), search_pkg_name.lower()):
                eco_key = pkg.get("registry", {}).get("ecosystem", "")
                pulse_eco = ECOSYSTEMS_MS_TO_PULSE.get(eco_key)
                
                if pulse_eco and pulse_eco in self._provider_map:
                    provider = self._provider_map[pulse_eco]
                    
                    version_exists = False
                    target_pkg_name = pkg.get("name") or search_pkg_name
                    if version:
                        ver_data = await self.ecosystems_client.get_package_version(
                            pkg.get("registry", {}).get("name", ""), target_pkg_name, version
                        )
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

        # ── Evidence Source 2: Native Registry Checks ──
        found_ecos = {c.ecosystem for c in candidates}
        
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            # If local identity hint exists and that ecosystem wasn't found by ecosyste.ms,
            # ALWAYS check it first — this is the primary fix for the Bootstrap problem.
            if local_eco and local_eco not in found_ecos and local_eco in self._provider_map:
                hint_provider = self._provider_map[local_eco]
                hint_candidate = await self._check_native_provider(client, hint_provider, search_pkg_name, version)
                if hint_candidate:
                    candidates.append(hint_candidate)
                    found_ecos.add(local_eco)

            # Check remaining providers and also native-verify any candidate with version_exists=False
            native_tasks = []
            for provider in self.providers:
                p_name = provider.manifest.name
                existing = [c for c in candidates if c.ecosystem.lower() == p_name.lower()]
                if not existing or not any(c.version_exists for c in existing):
                    native_tasks.append(self._check_native_provider(client, provider, search_pkg_name, version))
            
            if native_tasks:
                native_results = await asyncio.gather(*native_tasks)
                for nr in native_results:
                    if nr:
                        # Replace unverified candidate if present
                        candidates = [c for c in candidates if c.ecosystem.lower() != nr.ecosystem.lower()]
                        candidates.append(nr)

        # ── Smart Disambiguation & Pure Collision Check ──
        from pulse.ecosystems.smart_disambiguation import PackageDisambiguator
        any_version_verified = any(c.version_exists for c in candidates)
        if not any_version_verified:
            eval_res = PackageDisambiguator.evaluate(
                package_name=package_name,
                requested_version=version,
                candidate_ecosystem=candidates[0].ecosystem if candidates else None,
                candidate_version_exists=False,
                candidate_description=candidates[0].description if candidates else None
            )
            if eval_res.is_standalone:
                standalone_cand = PackageCandidate(
                    ecosystem="Standalone Software",
                    registry_name="NVD / Linux Distros",
                    package_name=package_name,
                    requested_version=version,
                    package_exists=True,
                    version_exists=True,
                    confidence=eval_res.confidence,
                    source="standalone_heuristic",
                    reason=eval_res.warning_message or "Resolved to Standalone Infrastructure / Web Server"
                )
                result.package_name = package_name
                result.ecosystem = "Standalone Software"
                result.registry_name = "NVD / Linux Distros"
                result.package_exists = True
                result.version_exists = True
                result.version_verified = True
                result.confidence = eval_res.confidence
                result.requires_user_selection = False
                result.resolution_reason = eval_res.warning_message or "Resolved to Standalone Infrastructure / Web Server"
                result.is_standalone = True
                result.warning_message = eval_res.warning_message
                result.cpe_candidates = eval_res.cpe_candidates or []
                result.candidates = [standalone_cand]
                return result

        # ── Score All Candidates ──
        for c in candidates:
            self._score_candidate(c, local_eco)

        candidates.sort(key=lambda x: x.confidence, reverse=True)

        # Filter out low confidence
        good_candidates = [c for c in candidates if c.confidence >= 50]
        if not good_candidates and candidates:
            good_candidates = [candidates[0]]
            
        result.candidates = good_candidates
        
        if not good_candidates:
            result.resolution_reason = "Package not found in any supported ecosystem."
            return result

        best = good_candidates[0]
        
        # ── Auto-Resolution Decision ──
        is_clearly_ahead = True
        if len(good_candidates) > 1:
            second_best = good_candidates[1]
            if best.confidence - second_best.confidence < 15:
                is_clearly_ahead = False
                
        strong_local = (local_eco and local_eco.lower() == best.ecosystem.lower())

        if (best.confidence >= 50 and is_clearly_ahead) or strong_local or len(good_candidates) == 1:
            result.package_name = best.package_name
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
            result.package_name = best.package_name
            result.package_exists = True
            result.version_exists = best.version_exists
            result.ecosystem = best.ecosystem
            result.registry_name = best.registry_name
            result.provider = best.provider
            result.alternative_candidates = good_candidates
            result.resolution_reason = "Ambiguous package identity or missing version."

        return result

