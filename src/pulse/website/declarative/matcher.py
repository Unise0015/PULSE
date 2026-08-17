"""
Matcher and Version Extractor for PULSE Declarative Web Technology Intelligence.
Provides pattern matching, SemVer 2.0 / CalVer grammar extraction, conservative range pinning,
and reusable evidence collection.
"""

import re
from typing import Optional, Tuple, Match
from pulse.website.declarative.models import PatternRule, DeclarativeEvidence


class PatternMatcher:
    """Helper for executing regex matches, extracting versions, and creating evidence records."""

    @staticmethod
    def normalize_version(version_str: str) -> Optional[str]:
        """
        Normalizes extracted version strings supporting SemVer 2.0 (with prerelease/build metadata)
        and CalVer (date-based versions like 2024.1.0, 24.04).
        """
        if not version_str or not isinstance(version_str, str):
            return None

        v = version_str.strip()
        
        # 1. Check for query param version (?ver=3.7.1 or ?v=5.3.2)
        qp_match = re.search(r"[?&](?:ver|v|version)=([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)*)", v, re.IGNORECASE)
        if qp_match:
            v = qp_match.group(1).strip(".")

        # 2. Check for npm/cdn version tag (@5.3.2 or @1.18.0)
        at_match = re.search(r"@([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)*)", v)
        if at_match:
            v = at_match.group(1).strip(".")

        # 3. Strip leading v. or v prefix
        if v.lower().startswith("v."):
            v = v[2:]
        elif v.lower().startswith("v") and len(v) > 1 and v[1].isdigit():
            v = v[1:]

        # 4. Search for SemVer 2.0 pattern (X.Y.Z-prerelease+build)
        semver_match = re.search(
            r"(\d+(?:\.\d+)+(?:-[a-zA-Z0-9._-]+)?(?:\+[a-zA-Z0-9._-]+)?)",
            v,
            re.IGNORECASE
        )
        if semver_match:
            ver_found = semver_match.group(1).strip(".")
            # Clean trailing suffixes
            ver_found = re.sub(r"[-.](?:min|prod|production|dev|development|bundle|chunk|module|esm|js|css)+$", "", ver_found, flags=re.IGNORECASE)
            return ver_found if ver_found else None

        # 5. Search for CalVer pattern (YYYY.MM.DD or YY.MM)
        calver_match = re.search(r"(20\d{2}\.(?:0?[1-9]|1[0-2])(?:\.\d+)?)", v)
        if calver_match:
            return calver_match.group(1)

        # 6. Single major digit fallback if unambiguous
        digit_match = re.match(r"^(\d+)$", v)
        if digit_match:
            return digit_match.group(1)

        return None

    @classmethod
    def extract_version(cls, rule: PatternRule, match: Optional[Match], text: str) -> Optional[str]:
        """Extracts version from capture group \1, \2, ternary templates, or matched text."""
        raw_version = None

        if rule.version_group:
            vg = rule.version_group.strip()
            
            # Ternary syntax: \1?if_group_1:if_else
            if "?" in vg and ":" in vg:
                try:
                    cond_part, else_part = vg.split(":", 1)
                    grp_ref, then_val = cond_part.split("?", 1)
                    grp_idx = int(grp_ref.lstrip("\\"))
                    if match and grp_idx <= len(match.groups()) and match.group(grp_idx):
                        matched_val = match.group(grp_idx)
                        target_sub = "\\" + str(grp_idx)
                        raw_version = then_val.replace(target_sub, matched_val) if target_sub in then_val else (then_val or matched_val)
                    else:
                        raw_version = else_part
                except Exception:
                    pass
            elif vg.startswith("\\"):
                try:
                    grp_idx = int(vg.lstrip("\\"))
                    if match and grp_idx <= len(match.groups()):
                        raw_version = match.group(grp_idx)
                except (ValueError, IndexError):
                    pass
            else:
                raw_version = vg

        # If rule had no explicit version group or group was empty, try extracting from match if available
        if not raw_version and match:
            for grp in match.groups():
                if grp and re.search(r"\d+\.\d+", str(grp)):
                    raw_version = str(grp)
                    break
            if not raw_version:
                raw_version = match.group(0)

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
        if not target_text and rule.raw_pattern != "":
            return None

        matched_str = None
        match = None

        if rule.raw_pattern == "":
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
