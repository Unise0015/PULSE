"""
Signature Loader for PULSE Declarative Web Intelligence.
Safely loads, parses, validates, and normalizes JSON technology signatures.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from pulse.website.declarative.models import PatternRule, TechnologyRule

logger = logging.getLogger(__name__)

# Default directory path for web signature files
DEFAULT_SIGNATURES_DIR = Path(__file__).parent.parent.parent / "data" / "web_signatures"


class SignatureLoader:
    """Loads and validates technology signature rules from JSON files."""

    def __init__(self, signatures_dir: Optional[Path] = None):
        self.signatures_dir = signatures_dir or DEFAULT_SIGNATURES_DIR
        self.categories: Dict[int, str] = {}
        self.technology_rules: Dict[str, TechnologyRule] = {}
        self._compiled_cache: Dict[str, Optional[re.Pattern]] = {}
        self.load_all()

    def _load_categories(self):
        """Loads category mapping from categories.json."""
        cat_file = self.signatures_dir / "categories.json"
        if not cat_file.exists():
            return
        try:
            with open(cat_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for cid_str, cat_info in data.items():
                        try:
                            cid = int(cid_str)
                            name = cat_info.get("name", f"Category {cid}") if isinstance(cat_info, dict) else str(cat_info)
                            self.categories[cid] = name
                        except ValueError:
                            pass
        except Exception as e:
            logger.warning("Error loading categories.json: %s", e)

    def parse_pattern_rule(self, raw_pattern: str) -> PatternRule:
        """Parses a pattern string with inline modifiers like \\;version:\\1\\;confidence:50."""
        parts = raw_pattern.split(r"\;")
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

        regex = None
        if pattern:
            if pattern in self._compiled_cache:
                regex = self._compiled_cache[pattern]
            else:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.debug("Failed to compile regex pattern '%s': %s", pattern, e)
                    regex = None
                self._compiled_cache[pattern] = regex

        return PatternRule(
            raw_pattern=pattern,
            regex=regex,
            version_group=version_group,
            confidence=confidence
        )

    def _parse_patterns_list(self, patterns_input: Any) -> List[PatternRule]:
        """Helper to convert a single string or list of strings into PatternRule objects."""
        if patterns_input is None:
            return []
        inputs = patterns_input if isinstance(patterns_input, list) else [patterns_input]
        rules = []
        for p in inputs:
            if isinstance(p, str):
                rules.append(self.parse_pattern_rule(p))
        return rules


    def load_all(self) -> Dict[str, TechnologyRule]:
        """Loads and parses all JSON signature files in signatures_dir."""
        self._load_categories()

        if not self.signatures_dir.exists():
            logger.warning("Signature directory does not exist: %s", self.signatures_dir)
            return self.technology_rules

        json_files = list(self.signatures_dir.glob("*.json"))
        loaded_count = 0

        for json_path in json_files:
            if json_path.name == "categories.json":
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    tech_dict = json.load(f)
                    if not isinstance(tech_dict, dict):
                        continue
                    for tech_name, tech_data in tech_dict.items():
                        if not isinstance(tech_data, dict):
                            continue
                        rule = self._build_technology_rule(tech_name, tech_data)
                        self.technology_rules[tech_name] = rule
                        loaded_count += 1
            except Exception as e:
                logger.warning("Skipping corrupted signature file %s: %s", json_path.name, e)

        logger.info("Successfully loaded %d technology rules from %d files.", loaded_count, len(json_files))
        return self.technology_rules

    def _build_technology_rule(self, tech_name: str, tech_data: Dict[str, Any]) -> TechnologyRule:
        """Constructs a normalized TechnologyRule object from raw JSON dictionary."""
        # Categories
        cats = []
        raw_cats = tech_data.get("cats", [])
        if isinstance(raw_cats, list):
            for cid in raw_cats:
                if isinstance(cid, int) and cid in self.categories:
                    cats.append(self.categories[cid])

        # Headers dict
        headers_rules: Dict[str, List[PatternRule]] = {}
        raw_headers = tech_data.get("headers")
        if isinstance(raw_headers, dict):
            for h_name, h_pats in raw_headers.items():
                headers_rules[h_name.lower().strip()] = self._parse_patterns_list(h_pats)

        # Cookies dict
        cookies_rules: Dict[str, List[PatternRule]] = {}
        raw_cookies = tech_data.get("cookies")
        if isinstance(raw_cookies, dict):
            for c_name, c_pats in raw_cookies.items():
                cookies_rules[c_name.lower().strip()] = self._parse_patterns_list(c_pats)

        # Meta dict
        meta_rules: Dict[str, List[PatternRule]] = {}
        raw_meta = tech_data.get("meta")
        if isinstance(raw_meta, dict):
            for m_name, m_pats in raw_meta.items():
                meta_rules[m_name.lower().strip()] = self._parse_patterns_list(m_pats)

        # HTML / Text
        html_rules = self._parse_patterns_list(tech_data.get("html") or tech_data.get("text"))

        # Scripts / ScriptSrc
        script_rules = self._parse_patterns_list(tech_data.get("scriptSrc") or tech_data.get("scripts"))

        # URL
        url_rules = self._parse_patterns_list(tech_data.get("url"))

        # CPEs
        cpes = []
        raw_cpe = tech_data.get("cpe")
        if isinstance(raw_cpe, str) and raw_cpe.strip():
            cpes.append(raw_cpe.strip())
        elif isinstance(raw_cpe, list):
            cpes.extend([c for c in raw_cpe if isinstance(c, str)])

        # Implies
        implies = []
        raw_implies = tech_data.get("implies")
        if isinstance(raw_implies, str):
            implies.append(raw_implies.split(r"\;")[0].strip())
        elif isinstance(raw_implies, list):
            for imp in raw_implies:
                if isinstance(imp, str):
                    implies.append(imp.split(r"\;")[0].strip())

        # Excludes
        excludes = []
        raw_excludes = tech_data.get("excludes")
        if isinstance(raw_excludes, str):
            excludes.append(raw_excludes.split(r"\;")[0].strip())
        elif isinstance(raw_excludes, list):
            for ex in raw_excludes:
                if isinstance(ex, str):
                    excludes.append(ex.split(r"\;")[0].strip())

        return TechnologyRule(
            name=tech_name,
            categories=cats,
            headers=headers_rules,
            cookies=cookies_rules,
            html=html_rules,
            scripts=script_rules,
            meta=meta_rules,
            url=url_rules,
            cpes=cpes,
            implies=implies,
            excludes=excludes
        )
