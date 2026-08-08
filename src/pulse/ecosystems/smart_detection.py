import asyncio
import httpx
import logging
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple, Optional, Dict
from pathlib import Path
from datetime import datetime, timedelta

from pulse.ecosystems.base import EcosystemRegistry, EcosystemPlugin, DetectionCandidate, ECOSYSTEM_REGISTRY_MAP
from pulse.ecosystems.detection import EcosystemDetector
from pulse.history.db import get_db_path

logger = logging.getLogger(__name__)

CACHE_TTL_DAYS = 30


class DetectionSource(Enum):
    """Standardized detection origin for diagnostics."""
    LOCAL_LOCKFILE = "Local Lockfile"
    NAMING_HEURISTIC = "Naming Heuristic"
    REGISTRY_LOOKUP = "Registry Lookup"
    CACHE = "Cache"
    USER_SELECTION = "User Selection"

class DetectionStatus(Enum):
    SUCCESS = "success"
    PACKAGE_NOT_FOUND = "package_not_found"
    VERSION_NOT_FOUND = "version_not_found"
    AMBIGUOUS = "ambiguous"
    NETWORK_ERROR = "network_error"
    OFFLINE = "offline"

@dataclass
class RegistryValidationResult:
    package_exists: bool
    version_exists: bool
    latest_available_version: Optional[str]
    network_error: bool
    http_status: Optional[int]


@dataclass
class DetectionResult:
    """Encapsulates the result of ecosystem detection with provider object."""
    status: DetectionStatus = DetectionStatus.SUCCESS
    provider: Optional[EcosystemPlugin] = None
    candidates: List[EcosystemPlugin] = field(default_factory=list)
    package_name: str = ""
    version: Optional[str] = None
    registry_name: Optional[str] = None
    latest_available_version: Optional[str] = None
    confidence: int = 0
    detection_source: DetectionSource = DetectionSource.REGISTRY_LOOKUP
    validation_errors: List[str] = field(default_factory=list)


@dataclass
class ResolutionScore:
    ecosystem: str
    validation: Optional[RegistryValidationResult] = None
    score: int = 0

    @property
    def confidence(self) -> int:
        return self.score


class SmartEcosystemDetector:
    def __init__(self, registry: EcosystemRegistry):
        self.registry = registry
        self.base_detector = EcosystemDetector(registry)
        self.db_path = get_db_path()

    def _get_cached_result(self, package_name: str) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ecosystem, detected_at FROM ecosystem_resolution_cache WHERE package_name = ?",
                    (package_name,)
                )
                row = cursor.fetchone()
                if row:
                    ts = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() - ts < timedelta(days=CACHE_TTL_DAYS):
                        return row[0]
                    else:
                        cursor.execute("DELETE FROM ecosystem_resolution_cache WHERE package_name = ?", (package_name,))
                        conn.commit()
        except sqlite3.Error:
            pass
        return None

    def _cache_result(self, package_name: str, ecosystem: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "REPLACE INTO ecosystem_resolution_cache (package_name, ecosystem, detected_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                    (package_name, ecosystem)
                )
                conn.commit()
        except sqlite3.Error:
            pass

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
                    has_version = version in data.get("releases", {})
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_npm(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            resp = await client.get(f"https://registry.npmjs.org/{name}")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("dist-tags", {}).get("latest")
                has_version = True
                if version:
                    has_version = version in data.get("versions", {})
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
                    has_version = any(v.get("num") == version for v in data.get("versions", []))
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
            resp = await client.get(f"https://packagist.org/packages/{name}.json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                pkg = data.get("package", {})
                versions = pkg.get("versions", {})
                latest = None
                for v in versions.keys():
                    if "dev" not in v and "alpha" not in v and "beta" not in v and "rc" not in v:
                        latest = v.lstrip("v")
                        break
                if not latest and versions:
                    latest = list(versions.keys())[0]
                has_version = True
                if version:
                    has_version = version in versions or f"v{version}" in versions
                return RegistryValidationResult(True, has_version, latest, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_nuget(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            resp = await client.get(f"https://api.nuget.org/v3/registration5-gz-semver2/{name.lower()}/index.json")
            if resp.status_code == 404:
                return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                # Nuget index json is complex, we'll just return True for version if package exists for now
                # In a real app we'd parse the pages
                return RegistryValidationResult(True, True, None, False, 200)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    def _encode_go_path(self, path: str) -> str:
        encoded = []
        for char in path:
            if char.isupper():
                encoded.append(f"!{char.lower()}")
            else:
                encoded.append(char)
        return "".join(encoded)

    async def _check_maven(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            query = f"g:{name}"
            if ":" in name:
                g, a = name.split(":", 1)
                query = f"g:\"{g}\" AND a:\"{a}\""
                
            resp = await client.get("https://search.maven.org/solrsearch/select", params={"q": query})
            if resp.status_code == 404:
                 return RegistryValidationResult(False, False, None, False, 404)
            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                if data.get("response", {}).get("numFound", 0) > 0 and docs:
                    latest = docs[0].get("latestVersion")
                    return RegistryValidationResult(True, True, latest, False, 200)
                else:
                    return RegistryValidationResult(False, False, None, False, 404)
            return RegistryValidationResult(False, False, None, True, resp.status_code)
        except Exception:
            return RegistryValidationResult(False, False, None, True, None)

    async def _check_go(self, client: httpx.AsyncClient, name: str, version: Optional[str]) -> RegistryValidationResult:
        try:
            encoded_name = self._encode_go_path(name)
            resp = await client.get(f"https://proxy.golang.org/{encoded_name}/@v/list")
            if resp.status_code == 404 or resp.status_code == 410:
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

    def _run_targeted_version_check(self, ecosystem: str, name: str, version: str) -> Tuple[bool, bool]:
        async def run_check():
            async with httpx.AsyncClient(timeout=1.5, follow_redirects=True) as client:
                if ecosystem == "Python":
                    return await self._check_pypi(client, name, version)
                elif ecosystem == "Node.js":
                    return await self._check_npm(client, name, version)
                elif ecosystem == "Rust":
                    return await self._check_crates(client, name, version)
                elif ecosystem == "Ruby":
                    return await self._check_rubygems(client, name, version)
                elif ecosystem == "Composer":
                    return await self._check_packagist(client, name, version)
                elif ecosystem == "NuGet":
                    return await self._check_nuget(client, name, version)
                elif ecosystem == "Maven":
                    return await self._check_maven(client, name, version)
                elif ecosystem == "Go":
                    return await self._check_go(client, name, version)
                return False, False
        try:
            return asyncio.run(run_check())
        except Exception:
            return False, False

    def detect(self, package_name: str, current_dir: Path, version: Optional[str] = None, offline: bool = False) -> Tuple[List[ResolutionScore], DetectionStatus]:
        local_candidates = self.base_detector.detect_ecosystem(package_name, current_dir)
        resolved = self.base_detector.resolve(local_candidates)
        
        # Stage 1: Offline mode
        if offline:
            return [ResolutionScore(ecosystem=c.ecosystem, score=c.confidence) for c in resolved], DetectionStatus.OFFLINE

        # Component 4: Short Package Heuristic
        # Disable early shortcut if name is short
        short_name = len(package_name) < 2
        
        # Early cache check if not short name
        cached_eco = None
        if not short_name:
            cached_eco = self._get_cached_result(package_name)
            if cached_eco:
                # If cached, we still want to verify the version if one is provided
                pass

        # Perform concurrent registry lookups
        ecosystems = ["Python", "Node.js", "Rust", "Ruby", "Composer", "NuGet", "Maven", "Go"]
        
        async def run_lookups():
            async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
                tasks = [
                    self._check_pypi(client, package_name, version),
                    self._check_npm(client, package_name, version),
                    self._check_crates(client, package_name, version),
                    self._check_rubygems(client, package_name, version),
                    self._check_packagist(client, package_name, version),
                    self._check_nuget(client, package_name, version),
                    self._check_maven(client, package_name, version),
                    self._check_go(client, package_name, version),
                ]
                return await asyncio.gather(*tasks)

        try:
            reg_results = asyncio.run(run_lookups())
        except Exception as e:
            logger.warning(f"Error running registry checks: {e}")
            return [ResolutionScore(ecosystem=c.ecosystem, score=c.confidence) for c in resolved], DetectionStatus.NETWORK_ERROR

        scores: List[ResolutionScore] = []
        all_network_errors = True
        package_found_anywhere = False
        version_found_anywhere = False

        for eco, reg_val in zip(ecosystems, reg_results):
            if not reg_val.network_error:
                all_network_errors = False
            if reg_val.package_exists:
                package_found_anywhere = True
            if reg_val.version_exists:
                version_found_anywhere = True

            heuristic_match = False
            local_cand = next((c for c in local_candidates if c.ecosystem == eco), None)
            if local_cand and local_cand.confidence >= 90:
                heuristic_match = True
            
            score_val = 0
            if heuristic_match:
                score_val += 150
            if reg_val.package_exists:
                score_val += 10
            if version and reg_val.version_exists:
                score_val += 100
                
            lockfile_map = {
                "Python": ["requirements.txt"],
                "Node.js": ["package.json", "package-lock.json"],
                "Rust": ["Cargo.toml", "Cargo.lock"],
                "Go": ["go.mod", "go.sum"],
                "Ruby": ["Gemfile", "Gemfile.lock"],
                "Composer": ["composer.json", "composer.lock"],
                "NuGet": ["packages.config"],
                "Maven": ["pom.xml"]
            }
            lockfile_exists = False
            for lf in lockfile_map.get(eco, []):
                if (current_dir / lf).exists():
                    lockfile_exists = True
                    break
            if lockfile_exists:
                score_val += 15
                
            scores.append(ResolutionScore(
                ecosystem=eco,
                validation=reg_val,
                score=score_val
            ))

        # Stage 4: Network Error
        if all_network_errors:
            return [ResolutionScore(ecosystem=c.ecosystem, score=c.confidence) for c in resolved], DetectionStatus.NETWORK_ERROR

        # Stage 3: Package Not Found
        if not package_found_anywhere:
            return [], DetectionStatus.PACKAGE_NOT_FOUND

        # Stage 5: Version Not Found
        if version and not version_found_anywhere:
            # Sort scores by those that have the package, to return the one with the latest_available_version
            valid_scores = [s for s in scores if s.validation and s.validation.package_exists]
            valid_scores.sort(key=lambda s: s.score, reverse=True)
            return valid_scores, DetectionStatus.VERSION_NOT_FOUND

        # Filter strictly for valid candidates
        if version:
            candidates = [s for s in scores if s.validation and s.validation.version_exists]
        else:
            candidates = [s for s in scores if s.validation and s.validation.package_exists]
            
        candidates.sort(key=lambda s: s.score, reverse=True)

        # Stage 6 & 7: Success or Ambiguous
        if len(candidates) == 1:
            self._cache_result(package_name, candidates[0].ecosystem)
            return candidates, DetectionStatus.SUCCESS
            
        if len(candidates) > 1:
            winner = candidates[0]
            runner_up = candidates[1]
            if winner.score >= 100 and (winner.score - runner_up.score) >= 50:
                self._cache_result(package_name, winner.ecosystem)
                return [winner], DetectionStatus.SUCCESS
            else:
                return candidates, DetectionStatus.AMBIGUOUS
                
        return [], DetectionStatus.PACKAGE_NOT_FOUND

    def _find_provider_for_ecosystem(self, ecosystem: str) -> Optional[EcosystemPlugin]:
        for provider in self.registry.get_all_providers():
            if provider.manifest.name == ecosystem:
                return provider
        return None

    def resolve_package(self, package_name: str, current_dir: Path, version: Optional[str] = None, offline: bool = False) -> DetectionResult:
        try:
            candidates, status = self.detect(package_name, current_dir, version, offline)
        except Exception as e:
            logger.error(f"Detection failed for {package_name}: {e}", exc_info=True)
            return DetectionResult(
                status=DetectionStatus.NETWORK_ERROR,
                candidates=self.registry.get_all_providers(),
                package_name=package_name,
                version=version
            )

        if status == DetectionStatus.PACKAGE_NOT_FOUND:
            return DetectionResult(status=status, package_name=package_name, version=version)
            
        if status == DetectionStatus.VERSION_NOT_FOUND:
            # We return the top candidate so the UI knows which registry failed to find the version and what the latest is
            top = candidates[0]
            provider = self._find_provider_for_ecosystem(top.ecosystem)
            latest = top.validation.latest_available_version if top.validation else None
            return DetectionResult(
                status=status,
                provider=provider,
                package_name=package_name,
                version=version,
                registry_name=provider.registry_name if provider else None,
                latest_available_version=latest
            )
            
        if status == DetectionStatus.NETWORK_ERROR or status == DetectionStatus.OFFLINE:
            # Fallback to heuristics
            if not candidates:
                return DetectionResult(
                    status=status,
                    candidates=self.registry.get_all_providers(),
                    package_name=package_name,
                    version=version
                )
            if len(candidates) == 1 or (len(candidates) > 1 and candidates[0].score - candidates[1].score >= 50):
                provider = self._find_provider_for_ecosystem(candidates[0].ecosystem)
                return DetectionResult(
                    status=DetectionStatus.SUCCESS if len(candidates) == 1 else DetectionStatus.AMBIGUOUS, # wait, actually SUCCESS if heuristic winner
                    provider=provider,
                    package_name=package_name,
                    version=version,
                    registry_name=provider.registry_name if provider else None,
                    confidence=candidates[0].score,
                    detection_source=DetectionSource.NAMING_HEURISTIC,
                    candidates=[provider] if provider else []
                )
            # Still ambiguous even with heuristics
            candidate_providers = [self._find_provider_for_ecosystem(c.ecosystem) for c in candidates]
            candidate_providers = [p for p in candidate_providers if p]
            return DetectionResult(
                status=DetectionStatus.AMBIGUOUS,
                package_name=package_name,
                version=version,
                candidates=candidate_providers
            )

        if status == DetectionStatus.SUCCESS:
            winner = candidates[0]
            provider = self._find_provider_for_ecosystem(winner.ecosystem)
            source = DetectionSource.REGISTRY_LOOKUP
            if winner.score >= 150:
                source = DetectionSource.NAMING_HEURISTIC
            elif winner.score == 95:
                source = DetectionSource.CACHE
                
            return DetectionResult(
                status=DetectionStatus.SUCCESS,
                provider=provider,
                package_name=package_name,
                version=version,
                registry_name=provider.registry_name if provider else None,
                confidence=winner.score,
                detection_source=source,
                candidates=[provider] if provider else [],
                latest_available_version=winner.validation.latest_available_version if winner.validation else None
            )

        if status == DetectionStatus.AMBIGUOUS:
            candidate_providers = [self._find_provider_for_ecosystem(c.ecosystem) for c in candidates]
            candidate_providers = [p for p in candidate_providers if p]
            return DetectionResult(
                status=DetectionStatus.AMBIGUOUS,
                package_name=package_name,
                version=version,
                candidates=candidate_providers
            )
            
        return DetectionResult(status=DetectionStatus.PACKAGE_NOT_FOUND, package_name=package_name, version=version)
