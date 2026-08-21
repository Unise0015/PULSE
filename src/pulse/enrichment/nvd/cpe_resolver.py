import json
import sqlite3
import logging
import time
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta

import httpx

from pulse.history.db import get_db_path
from pulse.config import get_setting

logger = logging.getLogger(__name__)

_CPE_DICT_CACHE_TTL_DAYS = 30
_DYNAMIC_CROSSWALK_TTL_DAYS = 90
_PROMOTION_THRESHOLD = 85
_ACCEPTANCE_THRESHOLD = 70

_NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _load_curated_crosswalk() -> Dict[str, Dict[str, Dict[str, str]]]:
    crosswalk_path = Path(__file__).parent.parent.parent / "data" / "ecosystem_cpe_crosswalk.json"
    try:
        with open(crosswalk_path, "r") as f:
            data = json.load(f)
        # Remove metadata key
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Could not load curated CPE crosswalk: %s", e)
        return {}


# Module-level cache loaded once
_CURATED_CROSSWALK: Optional[Dict] = None


def _get_curated_crosswalk() -> Dict:
    global _CURATED_CROSSWALK
    if _CURATED_CROSSWALK is None:
        _CURATED_CROSSWALK = _load_curated_crosswalk()
    return _CURATED_CROSSWALK


class CPEResolverResult:
    """Result of a CPE resolution attempt."""

    def __init__(
        self,
        vendor: str,
        product: str,
        cpe_uri: str,
        confidence: int,
        tier: str,
        source: str = "",
    ):
        self.vendor = vendor
        self.product = product
        self.cpe_uri = cpe_uri
        self.confidence = confidence
        self.tier = tier       # "curated", "dynamic", "api", "heuristic"
        self.source = source

    def __repr__(self):
        return f"CPEResolverResult({self.cpe_uri}, conf={self.confidence}, tier={self.tier})"


class TieredCPEResolver:
    """3-Tier CPE Resolution Engine.

    Tier 1: Curated crosswalk (ecosystem_cpe_crosswalk.json) + dynamic crosswalk (SQLite).
    Tier 2: NVD CPE Dictionary API with normalized 0-100 ranking.
    Tier 3: Heuristic fallback (vendor=product=package_name).
    """

    def __init__(self):
        self.db_path = get_db_path()
        self.api_key = get_setting("NVD_API_KEY")
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        self.client = httpx.Client(timeout=20.0, headers=headers)
        self.delay_between_reqs = 0.6 if self.api_key else 6.0

    def resolve(self, package_name: str, ecosystem: str) -> Optional[CPEResolverResult]:
        """Resolve a package to its best CPE match using the 3-tier pipeline."""
        # Tier 1: Curated crosswalk
        result = self._tier1_curated(package_name, ecosystem)
        if result:
            return result

        # Tier 1b: Dynamic crosswalk (auto-promoted from Tier 2)
        result = self._tier1_dynamic(package_name, ecosystem)
        if result:
            return result

        # Tier 2: NVD CPE Dictionary API with ranking
        result = self._tier2_api(package_name, ecosystem)
        if result:
            return result

        # Tier 3: Heuristic fallback
        return self._tier3_heuristic(package_name, ecosystem)

    # -- Tier 1: Curated Crosswalk -------------------------------------------

    def _tier1_curated(self, package_name: str, ecosystem: str) -> Optional[CPEResolverResult]:
        crosswalk = _get_curated_crosswalk()
        norm_eco = self._normalize_ecosystem(ecosystem)

        # Check ecosystem-specific mapping
        eco_map = crosswalk.get(norm_eco, {})
        entry = eco_map.get(package_name) or eco_map.get(package_name.lower())

        # Also check infrastructure mapping
        if not entry:
            infra_map = crosswalk.get("infrastructure", {})
            entry = infra_map.get(package_name.lower())

        if entry:
            return CPEResolverResult(
                vendor=entry["vendor"],
                product=entry["product"],
                cpe_uri=entry["cpe"],
                confidence=100,
                tier="curated",
                source="ecosystem_cpe_crosswalk.json",
            )
        return None

    # -- Tier 1b: Dynamic Crosswalk ------------------------------------------

    def _tier1_dynamic(self, package_name: str, ecosystem: str) -> Optional[CPEResolverResult]:
        norm_eco = self._normalize_ecosystem(ecosystem)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT cpe_23_uri, vendor, product, confidence, promoted_at "
                    "FROM dynamic_cpe_crosswalk WHERE ecosystem = ? AND package_name = ?",
                    (norm_eco, package_name.lower()),
                )
                row = cursor.fetchone()
                if row:
                    promoted_at = datetime.strptime(row[4], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() - promoted_at < timedelta(days=_DYNAMIC_CROSSWALK_TTL_DAYS):
                        return CPEResolverResult(
                            vendor=row[1],
                            product=row[2],
                            cpe_uri=row[0],
                            confidence=row[3],
                            tier="dynamic",
                            source="dynamic_cpe_crosswalk",
                        )
                    else:
                        # Expired -- delete and fall through to Tier 2 for revalidation
                        cursor.execute(
                            "DELETE FROM dynamic_cpe_crosswalk WHERE ecosystem = ? AND package_name = ?",
                            (norm_eco, package_name.lower()),
                        )
                        conn.commit()
        except sqlite3.Error as e:
            logger.debug("Dynamic crosswalk lookup failed: %s", e)
        return None

    # -- Tier 2: NVD CPE Dictionary API + Ranking ----------------------------

    def _tier2_api(self, package_name: str, ecosystem: str) -> Optional[CPEResolverResult]:
        norm_eco = self._normalize_ecosystem(ecosystem)
        norm_pkg = package_name.lower()

        # Check dictionary cache first
        cached = self._read_cpe_dict_cache(norm_pkg)
        if cached is not None:
            if not cached:
                return None
            best = self._rank_candidates(cached, norm_pkg, norm_eco)
            if best:
                return best

        # Fetch from NVD CPE Dictionary API
        candidates = self._fetch_cpe_dictionary(norm_pkg)
        if candidates is None:
            return None

        # Cache raw results
        self._write_cpe_dict_cache(norm_pkg, candidates)

        if not candidates:
            return None

        best = self._rank_candidates(candidates, norm_pkg, norm_eco)
        if best and best.confidence >= _PROMOTION_THRESHOLD:
            self._promote_to_dynamic(norm_eco, norm_pkg, best)
        return best

    def _fetch_cpe_dictionary(self, keyword: str) -> Optional[List[Dict[str, Any]]]:
        """Query NVD CPE Dictionary API for matching CPEs."""
        try:
            resp = self.client.get(
                _NVD_CPE_API_URL,
                params={"keywordSearch": keyword, "resultsPerPage": 20},
            )
            resp.raise_for_status()
            data = resp.json()
            products = data.get("products", [])

            candidates = []
            for prod in products:
                cpe = prod.get("cpe", {})
                cpe_name = cpe.get("cpeName", "")
                deprecated = cpe.get("deprecated", False)
                titles = cpe.get("titles", [])
                refs = cpe.get("refs", [])

                if not cpe_name or not cpe_name.startswith("cpe:2.3:"):
                    continue

                parts = cpe_name.split(":")
                if len(parts) < 6:
                    continue

                candidates.append({
                    "cpe_name": cpe_name,
                    "vendor": parts[3],
                    "product": parts[4],
                    "deprecated": deprecated,
                    "titles": [t.get("title", "") for t in titles if isinstance(t, dict)],
                    "refs": [r.get("ref", "") for r in refs if isinstance(r, dict)],
                })

            time.sleep(self.delay_between_reqs)
            return candidates

        except httpx.TimeoutException:
            logger.debug("NVD CPE Dictionary API timed out for keyword: %s", keyword)
        except httpx.HTTPStatusError as e:
            logger.debug("NVD CPE Dictionary API HTTP %s for keyword: %s", e.response.status_code, keyword)
        except Exception as e:
            logger.debug("NVD CPE Dictionary API error for keyword %s: %s", keyword, e)
        return None

    def _rank_candidates(
        self, candidates: List[Dict], package_name: str, ecosystem: str
    ) -> Optional[CPEResolverResult]:
        """Rank CPE candidates using normalized 0-100 scoring.

        Scoring breakdown:
            +50  Exact product name match
            +30  Vendor/org relevance
            +20  Title/ref corroboration
            -40  Deprecated CPE penalty
        """
        scored = []
        eco_keywords = self._get_ecosystem_keywords(ecosystem)

        for c in candidates:
            score = 0
            product = c.get("product", "").lower()
            vendor = c.get("vendor", "").lower()

            # +50: Exact product name match
            if product == package_name.lower():
                score += 50

            # +30: Vendor relevance
            vendor_relevant = (
                vendor == package_name.lower()
                or any(kw in vendor for kw in eco_keywords)
                or product in vendor
                or vendor in product
            )
            if vendor_relevant:
                score += 30

            # +20: Title/ref corroboration
            titles_text = " ".join(c.get("titles", [])).lower()
            refs_text = " ".join(c.get("refs", [])).lower()
            corroboration = any(
                kw in titles_text or kw in refs_text
                for kw in eco_keywords
            )
            if corroboration:
                score += 20

            # -40: Deprecated penalty
            if c.get("deprecated", False):
                score -= 40

            # Clamp to 0-100
            score = max(0, min(100, score))

            if score >= _ACCEPTANCE_THRESHOLD:
                scored.append((score, c))

        if not scored:
            return None

        # Sort by score descending, take best
        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best = scored[0]

        return CPEResolverResult(
            vendor=best["vendor"],
            product=best["product"],
            cpe_uri=f"cpe:2.3:a:{best['vendor']}:{best['product']}",
            confidence=best_score,
            tier="api",
            source="nvd_cpe_dictionary",
        )

    def _promote_to_dynamic(self, ecosystem: str, package_name: str, result: CPEResolverResult) -> None:
        """Auto-promote a high-confidence Tier 2 result to dynamic crosswalk."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "REPLACE INTO dynamic_cpe_crosswalk "
                    "(ecosystem, package_name, cpe_23_uri, vendor, product, confidence, promoted_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (ecosystem, package_name, result.cpe_uri, result.vendor, result.product, result.confidence),
                )
                conn.commit()
                logger.debug(
                    "Auto-promoted CPE mapping: %s:%s -> %s (confidence=%d)",
                    ecosystem, package_name, result.cpe_uri, result.confidence,
                )
        except sqlite3.Error as e:
            logger.debug("Dynamic crosswalk promotion failed: %s", e)

    # -- Tier 3: Heuristic Fallback ------------------------------------------

    def _tier3_heuristic(self, package_name: str, ecosystem: str) -> Optional[CPEResolverResult]:
        """Last-resort heuristic: vendor=product=package_name."""
        norm = package_name.lower().replace("-", "_")
        return CPEResolverResult(
            vendor=norm,
            product=norm,
            cpe_uri=f"cpe:2.3:a:{norm}:{norm}",
            confidence=30,
            tier="heuristic",
            source="heuristic_fallback",
        )

    # -- Cache helpers -------------------------------------------------------

    def _read_cpe_dict_cache(self, keyword: str) -> Optional[List[Dict]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT cpe_23_uri, vendor, product, confidence, deprecated, titles_json, refs_json, timestamp "
                    "FROM cpe_dictionary_cache WHERE keyword = ?",
                    (keyword,),
                )
                rows = cursor.fetchall()
                if not rows:
                    return None
                # Check TTL on first row
                try:
                    ts = datetime.strptime(rows[0][7], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() - ts >= timedelta(days=_CPE_DICT_CACHE_TTL_DAYS):
                        cursor.execute("DELETE FROM cpe_dictionary_cache WHERE keyword = ?", (keyword,))
                        conn.commit()
                        return None
                except (ValueError, TypeError):
                    return None

                candidates = []
                for row in rows:
                    candidates.append({
                        "cpe_name": row[0],
                        "vendor": row[1],
                        "product": row[2],
                        "deprecated": bool(row[4]),
                        "titles": json.loads(row[5]) if row[5] else [],
                        "refs": json.loads(row[6]) if row[6] else [],
                    })
                return candidates
        except sqlite3.Error as e:
            logger.debug("CPE dictionary cache read failed: %s", e)
            return None

    def _write_cpe_dict_cache(self, keyword: str, candidates: List[Dict]) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Clear old entries for this keyword
                cursor.execute("DELETE FROM cpe_dictionary_cache WHERE keyword = ?", (keyword,))
                for c in candidates:
                    cursor.execute(
                        "INSERT INTO cpe_dictionary_cache "
                        "(keyword, cpe_23_uri, vendor, product, confidence, deprecated, titles_json, refs_json) "
                        "VALUES (?, ?, ?, ?, 0, ?, ?, ?)",
                        (
                            keyword,
                            c.get("cpe_name", ""),
                            c.get("vendor", ""),
                            c.get("product", ""),
                            1 if c.get("deprecated") else 0,
                            json.dumps(c.get("titles", [])),
                            json.dumps(c.get("refs", [])),
                        ),
                    )
                conn.commit()
        except sqlite3.Error as e:
            logger.debug("CPE dictionary cache write failed: %s", e)

    # -- Demotion / Cache Eviction -------------------------------------------

    def forget_cpe_mapping(self, package_name: str, ecosystem: Optional[str] = None) -> bool:
        """Evict a package from dynamic crosswalk and dictionary cache.

        Returns True if any rows were deleted.
        """
        deleted = False
        norm_pkg = package_name.lower()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if ecosystem:
                    norm_eco = self._normalize_ecosystem(ecosystem)
                    cursor.execute(
                        "DELETE FROM dynamic_cpe_crosswalk WHERE ecosystem = ? AND package_name = ?",
                        (norm_eco, norm_pkg),
                    )
                else:
                    cursor.execute(
                        "DELETE FROM dynamic_cpe_crosswalk WHERE package_name = ?",
                        (norm_pkg,),
                    )
                if cursor.rowcount > 0:
                    deleted = True

                cursor.execute(
                    "DELETE FROM cpe_dictionary_cache WHERE keyword = ?",
                    (norm_pkg,),
                )
                if cursor.rowcount > 0:
                    deleted = True
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("CPE mapping eviction failed: %s", e)
        return deleted

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _normalize_ecosystem(ecosystem: str) -> str:
        eco = ecosystem.lower()
        mapping = {
            "python": "pypi", "pypi": "pypi",
            "npm": "npm", "node": "npm", "node.js": "npm",
            "rust": "crates.io", "cargo": "crates.io", "crates.io": "crates.io",
            "go": "Go", "golang": "Go",
            "ruby": "RubyGems", "rubygems": "RubyGems",
            "composer": "Packagist", "php": "Packagist", "packagist": "Packagist",
            "maven": "Maven", "java": "Maven",
            "nuget": "NuGet", ".net": "NuGet", "dotnet": "NuGet",
        }
        return mapping.get(eco, eco)

    @staticmethod
    def _get_ecosystem_keywords(ecosystem: str) -> List[str]:
        eco = ecosystem.lower()
        keywords_map = {
            "pypi": ["python", "pypi", "pip"],
            "npm": ["node", "npm", "javascript", "js"],
            "crates.io": ["rust", "cargo", "crate"],
            "Go": ["go", "golang"],
            "RubyGems": ["ruby", "gem", "rubygems"],
            "Packagist": ["php", "composer", "packagist"],
            "Maven": ["java", "maven", "apache"],
            "NuGet": ["dotnet", ".net", "nuget", "microsoft"],
        }
        return keywords_map.get(eco, [eco])
