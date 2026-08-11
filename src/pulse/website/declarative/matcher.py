"""
Matcher and Version Extractor for PULSE Declarative Web Technology Intelligence.
Provides pattern matching, reusable version extraction, version normalization, and evidence collection.
"""

import re
from typing import Optional, Tuple, Match
from pulse.website.declarative.models import PatternRule, DeclarativeEvidence


class PatternMatcher:
    """Helper for executing regex matches, extracting versions, and creating evidence records."""

    @staticmethod
    def normalize_version(version_str: str) -> Optional[str]:
        """Normalizes extracted version strings (e.g. 'v1.2.3' -> '1.2.3', 'jquery.js?v=3.7.1' -> '3.7.1')."""
        if not version_str or not isinstance(version_str, str):
            return None

        v = version_str.strip()
        # Search for semver or digit pattern in version_str first
        m = re.search(r"(?:v\.?)?(\d+(?:\.\d+)+(?:-[a-zA-Z0-9\.]+|[a-zA-Z0-9\.]+)?|\d+)", v, re.IGNORECASE)
        if m:
            ver_found = m.group(0).strip(".")
            if ver_found.lower().startswith("v."):
                ver_found = ver_found[2:]
            elif ver_found.lower().startswith("v"):
                ver_found = ver_found[1:]
            return ver_found if ver_found else None

        return None

    @classmethod
    def extract_version(cls, rule: PatternRule, match: Optional[Match], text: str) -> Optional[str]:
        """Extracts version from capture group \\1, \\2 or literal template."""
        if not rule.version_group:
            return None

        vg = rule.version_group.strip()
        raw_version = None

        if vg.startswith("\\"):
            try:
                grp_idx = int(vg[1:])
                if match and grp_idx <= len(match.groups()):
                    raw_version = match.group(grp_idx)
            except (ValueError, IndexError):
                pass
        elif not vg.startswith("\\"):
            raw_version = vg

        return cls.normalize_version(raw_version) if raw_version else None

    @classmethod
    def match_rule(
        cls,
        rule: PatternRule,
        target_text: str,
        source: str,
        header_name: Optional[str] = None,
        cookie_name: Optional[str] = None,
        meta_name: Optional[str] = None
    ) -> Optional[Tuple[DeclarativeEvidence, Optional[str]]]:
        """
        Evaluates a PatternRule against target text.
        Returns a tuple of (DeclarativeEvidence, extracted_version) if matched.
        """
        matched_str = None
        match = None

        if rule.raw_pattern == "":
            # Empty pattern indicates key presence match (e.g. cookie name exists)
            matched_str = header_name or cookie_name or meta_name or "present"
        elif rule.regex:
            match = rule.regex.search(target_text)
            if match:
                matched_str = match.group(0)
        elif rule.raw_pattern and rule.raw_pattern.lower() in target_text.lower():
            matched_str = rule.raw_pattern

        if matched_str is None:
            return None

        version = cls.extract_version(rule, match, target_text)

        evidence = DeclarativeEvidence(
            source=source,
            matched_value=matched_str[:120],
            pattern=rule.raw_pattern,
            confidence=rule.confidence,
            header_name=header_name,
            cookie_name=cookie_name,
            meta_name=meta_name,
            version=version
        )

        return evidence, version

