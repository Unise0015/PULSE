"""
Declarative Signature Engine for PULSE Web Subsystem.
Parses Wappalyzer-style JSON technology signatures, builds pre-filtering indexes,
and executes fast detection with version extraction and implication expansion.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from pulse.domain.models import TechnologyFingerprint, CPECandidate

logger = logging.getLogger(__name__)

# Default path to JSON signatures directory
SIGNATURES_DIR = Path(__file__).parent.parent / "data" / "web_signatures"


class ParsedRule:
    """Represents a single parsed detection pattern with modifiers."""
    __slots__ = ("raw_pattern", "regex", "version_group", "confidence")

    def __init__(self, raw_pattern: str, regex: Optional[re.Pattern], version_group: Optional[str], confidence: int):
        self.raw_pattern = raw_pattern
        self.regex = regex
        self.version_group = version_group
        self.confidence = confidence


class DeclarativeSignatureEngine:
    """Fast, pre-filtered technology detection engine using Wappalyzer-compatible JSON signatures."""

    def __init__(self, signatures_dir: Optional[Path] = None):
        self.signatures_dir = signatures_dir or SIGNATURES_DIR
        self.technologies: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[int, str] = {}

        # Pre-filtering indexes for maximum performance (< 150ms)
        self.header_index: Dict[str, List[Tuple[str, ParsedRule]]] = {}      # header_name -> [(tech_name, ParsedRule)]
        self.cookie_index: Dict[str, List[Tuple[str, ParsedRule]]] = {}      # cookie_name -> [(tech_name, ParsedRule)]
        self.meta_index: Dict[str, List[Tuple[str, ParsedRule]]] = {}        # meta_name -> [(tech_name, ParsedRule)]
        self.script_src_rules: List[Tuple[str, ParsedRule]] = []             # [(tech_name, ParsedRule)]
        self.html_rules: List[Tuple[str, ParsedRule]] = []                   # [(tech_name, ParsedRule)]
        self.url_rules: List[Tuple[str, ParsedRule]] = []                    # [(tech_name, ParsedRule)]

        self._compiled_cache: Dict[str, Optional[re.Pattern]] = {}
        self._load_categories()
        self._load_signatures()

    def _load_categories(self):
        """Loads category ID mapping (e.g. 1 -> 'CMS', 6 -> 'Web Server')."""
        cat_file = self.signatures_dir / "categories.json"
        if not cat_file.exists():
            return
        try:
            with open(cat_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for cat_id, cat_info in data.items():
                    try:
                        cid = int(cat_id)
                        name = cat_info.get("name", f"Category {cid}") if isinstance(cat_info, dict) else str(cat_info)
                        self.categories[cid] = name
                    except ValueError:
                        pass
        except Exception as e:
            logger.warning("Failed to load categories.json: %s", e)

    def _parse_pattern(self, raw_str: str) -> ParsedRule:
        """Parses a Wappalyzer pattern string with inline modifiers like ;version:\\1;confidence:50."""
        parts = raw_str.split(r"\;")
        pattern = parts[0]
        version_group = None
        confidence = 100

        for modifier in parts[1:]:
            if modifier.startswith("version:"):
                version_group = modifier[8:]
            elif modifier.startswith("confidence:"):
                try:
                    confidence = int(modifier[11:])
                except ValueError:
                    pass

        # Compile regex
        regex = None
        if pattern:
            if pattern in self._compiled_cache:
                regex = self._compiled_cache[pattern]
            else:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    # Fallback to literal search if regex compilation fails
                    regex = None
                self._compiled_cache[pattern] = regex

        return ParsedRule(pattern, regex, version_group, confidence)

    def _load_signatures(self):
        """Loads and indexes all JSON signature files."""
        if not self.signatures_dir.exists():
            logger.warning("Web signatures directory not found: %s", self.signatures_dir)
            return

        json_files = list(self.signatures_dir.glob("*.json"))
        count = 0

        for json_file in json_files:
            if json_file.name == "categories.json":
                continue
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    tech_data_map = json.load(f)
                    if not isinstance(tech_data_map, dict):
                        continue
                    for tech_name, tech_info in tech_data_map.items():
                        if not isinstance(tech_info, dict):
                            continue
                        self.technologies[tech_name] = tech_info
                        self._index_technology(tech_name, tech_info)
                        count += 1
            except Exception as e:
                logger.debug("Error loading web signature file %s: %s", json_file.name, e)

        logger.info("Loaded %d web technology signatures across %d JSON files.", count, len(json_files))

    def _index_technology(self, tech_name: str, tech_info: Dict[str, Any]):
        """Indexes technology rules into fast lookup tables for headers, cookies, meta, scripts, HTML."""
        # Index headers
        headers = tech_info.get("headers")
        if isinstance(headers, dict):
            for h_name, patterns in headers.items():
                h_key = h_name.lower().strip()
                pat_list = patterns if isinstance(patterns, list) else [patterns]
                for p in pat_list:
                    if isinstance(p, str):
                        rule = self._parse_pattern(p)
                        self.header_index.setdefault(h_key, []).append((tech_name, rule))

        # Index cookies
        cookies = tech_info.get("cookies")
        if isinstance(cookies, dict):
            for c_name, patterns in cookies.items():
                c_key = c_name.lower().strip()
                pat_list = patterns if isinstance(patterns, list) else [patterns]
                for p in pat_list:
                    if isinstance(p, str):
                        rule = self._parse_pattern(p)
                        self.cookie_index.setdefault(c_key, []).append((tech_name, rule))

        # Index meta tags
        meta = tech_info.get("meta")
        if isinstance(meta, dict):
            for m_name, patterns in meta.items():
                m_key = m_name.lower().strip()
                pat_list = patterns if isinstance(patterns, list) else [patterns]
                for p in pat_list:
                    if isinstance(p, str):
                        rule = self._parse_pattern(p)
                        self.meta_index.setdefault(m_key, []).append((tech_name, rule))

        # Index scriptSrc / scripts
        script_src = tech_info.get("scriptSrc") or tech_info.get("scripts")
        if script_src:
            pat_list = script_src if isinstance(script_src, list) else [script_src]
            for p in pat_list:
                if isinstance(p, str):
                    rule = self._parse_pattern(p)
                    self.script_src_rules.append((tech_name, rule))

        # Index HTML
        html_pats = tech_info.get("html") or tech_info.get("text")
        if html_pats:
            pat_list = html_pats if isinstance(html_pats, list) else [html_pats]
            for p in pat_list:
                if isinstance(p, str):
                    rule = self._parse_pattern(p)
                    self.html_rules.append((tech_name, rule))

        # Index URL patterns
        url_pats = tech_info.get("url")
        if url_pats:
            pat_list = url_pats if isinstance(url_pats, list) else [url_pats]
            for p in pat_list:
                if isinstance(p, str):
                    rule = self._parse_pattern(p)
                    self.url_rules.append((tech_name, rule))

    def _extract_version(self, rule: ParsedRule, match: re.Match, text: str) -> Optional[str]:
        """Extracts version from regex capture group or static template."""
        if not rule.version_group:
            return None

        vg = rule.version_group.strip()
        if vg.startswith("\\"):
            try:
                grp_idx = int(vg[1:])
                if match and grp_idx <= len(match.groups()):
                    val = match.group(grp_idx)
                    return val.strip() if val else None
            except (ValueError, IndexError):
                pass
        elif not vg.startswith("\\"):
            return vg

        return None


    def _get_category_name(self, tech_info: Dict[str, Any]) -> str:
        """Resolves human category name from category IDs."""
        cat_ids = tech_info.get("cats", [])
        if isinstance(cat_ids, list) and cat_ids:
            first_id = cat_ids[0]
            if isinstance(first_id, int) and first_id in self.categories:
                return self.categories[first_id]
        return "Web Technology"

    def analyze(
        self,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        html_body: str,
        script_urls: Optional[List[str]] = None
    ) -> List[TechnologyFingerprint]:
        """
        Executes fast, pre-filtered technology analysis against the given HTTP response.
        Returns a list of TechnologyFingerprint objects with confidence scores and CPEs.
        """
        detected: Dict[str, Dict[str, Any]] = {} # tech_name -> {confidence, version, category, cpe}

        def record_match(tech_name: str, rule: ParsedRule, match: Optional[re.Match], match_text: str):
            tech_info = self.technologies.get(tech_name, {})
            version = self._extract_version(rule, match, match_text) if match else None
            cat_name = self._get_category_name(tech_info)
            cpe = tech_info.get("cpe")

            if tech_name not in detected:
                detected[tech_name] = {
                    "confidence": rule.confidence,
                    "version": version,
                    "category": cat_name,
                    "cpe": cpe
                }
            else:
                # Upgrade confidence or version if better match found
                existing = detected[tech_name]
                existing["confidence"] = min(100, existing["confidence"] + rule.confidence)
                if not existing["version"] and version:
                    existing["version"] = version
                if not existing["cpe"] and cpe:
                    existing["cpe"] = cpe

        # --- STEP 1: Pre-filtered Headers Check ---
        for h_key, h_val in headers.items():
            h_key_lower = h_key.lower().strip()
            if h_key_lower in self.header_index:
                for tech_name, rule in self.header_index[h_key_lower]:
                    if rule.regex:
                        m = rule.regex.search(h_val)
                        if m:
                            record_match(tech_name, rule, m, h_val)
                    elif rule.raw_pattern and rule.raw_pattern.lower() in h_val.lower():
                        record_match(tech_name, rule, None, h_val)

        # --- STEP 2: Pre-filtered Cookies Check ---
        for c_key, c_val in cookies.items():
            c_key_lower = c_key.lower().strip()
            if c_key_lower in self.cookie_index:
                for tech_name, rule in self.cookie_index[c_key_lower]:
                    if rule.regex:
                        m = rule.regex.search(c_val)
                        if m:
                            record_match(tech_name, rule, m, c_val)
                    elif rule.raw_pattern and rule.raw_pattern.lower() in c_val.lower():
                        record_match(tech_name, rule, None, c_val)

        # --- STEP 3: Script Src Check ---
        if script_urls:
            script_blob = "\n".join(script_urls)
            for tech_name, rule in self.script_src_rules:
                if rule.regex:
                    m = rule.regex.search(script_blob)
                    if m:
                        record_match(tech_name, rule, m, script_blob)
                elif rule.raw_pattern and rule.raw_pattern.lower() in script_blob.lower():
                    record_match(tech_name, rule, None, script_blob)

        # --- STEP 4: Meta Tags Check ---
        if html_body and ("meta" in html_body.lower() or "generator" in html_body.lower()):
            # Parse generator meta tags
            meta_matches = re.findall(r'<meta\s+name=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
            for m_name, m_val in meta_matches:
                m_name_lower = m_name.lower().strip()
                if m_name_lower in self.meta_index:
                    for tech_name, rule in self.meta_index[m_name_lower]:
                        if rule.regex:
                            m = rule.regex.search(m_val)
                            if m:
                                record_match(tech_name, rule, m, m_val)
                        elif rule.raw_pattern and rule.raw_pattern.lower() in m_val.lower():
                            record_match(tech_name, rule, None, m_val)

        # --- STEP 5: Fast HTML Body Check ---
        if html_body:
            for tech_name, rule in self.html_rules:
                # Fast check to avoid heavy regex on 2MB HTML
                if rule.raw_pattern and len(rule.raw_pattern) > 3 and rule.raw_pattern.lower() not in html_body.lower():
                    continue
                if rule.regex:
                    m = rule.regex.search(html_body)
                    if m:
                        record_match(tech_name, rule, m, html_body)

        # --- STEP 6: Implication Graph Expansion ---
        # e.g., Next.js -> React, WordPress -> PHP & MySQL
        visited_implies: Set[str] = set()
        to_process = list(detected.keys())

        while to_process:
            current_tech = to_process.pop(0)
            if current_tech in visited_implies:
                continue
            visited_implies.add(current_tech)

            tech_info = self.technologies.get(current_tech, {})
            implies = tech_info.get("implies")
            if implies:
                implied_list = implies if isinstance(implies, list) else [implies]
                for implied_name in implied_list:
                    if not isinstance(implied_name, str):
                        continue
                    clean_implied = implied_name.split(r"\;")[0].strip()
                    if clean_implied not in detected:
                        imp_info = self.technologies.get(clean_implied, {})
                        cat_name = self._get_category_name(imp_info)
                        cpe = imp_info.get("cpe")
                        detected[clean_implied] = {
                            "confidence": 90,
                            "version": None,
                            "category": cat_name,
                            "cpe": cpe
                        }
                        to_process.append(clean_implied)

        # --- STEP 7: Exclusion Rules Engine ---
        excluded_techs: Set[str] = set()
        for tech_name in detected.keys():
            tech_info = self.technologies.get(tech_name, {})
            excludes = tech_info.get("excludes")
            if excludes:
                ex_list = excludes if isinstance(excludes, list) else [excludes]
                for ex in ex_list:
                    if isinstance(ex, str):
                        excluded_techs.add(ex.split(r"\;")[0].strip())

        # --- STEP 8: Construct Result Models ---
        results: List[TechnologyFingerprint] = []
        for name, data in detected.items():
            if name in excluded_techs:
                continue

            cpe_cands = []
            if data.get("cpe"):
                cpe_cands.append(CPECandidate(cpe=data["cpe"], confidence=data["confidence"]))

            results.append(
                TechnologyFingerprint(
                    name=name,
                    category=data["category"],
                    version=data["version"],
                    confidence=data["confidence"],
                    cpe_candidates=cpe_cands
                )
            )

        return results

