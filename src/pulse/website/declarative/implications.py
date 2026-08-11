"""
Implication & Exclusion Resolver for PULSE Declarative Web Intelligence.
Recursively resolves technology relationships while protecting against infinite cycles,
setting inferred=True and inferred_from flags.
"""

import logging
from typing import Dict, List, Set, Any
from pulse.website.declarative.models import TechnologyRule
from pulse.domain.models import TechnologyFingerprint

logger = logging.getLogger(__name__)


class ImplicationResolver:
    """Handles technology implications and exclusion precedence rules."""

    @classmethod
    def resolve(
        cls,
        detected_map: Dict[str, Dict[str, Any]],
        technology_rules: Dict[str, TechnologyRule]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Recursively resolves implied technologies and enforces exclusions.
        
        Args:
            detected_map: Dict mapping tech_name -> {confidence, version, category, cpes, evidence, inferred, inferred_from}
            technology_rules: Loaded TechnologyRule lookup table
        """
        visited_implies: Set[str] = set()
        queue = list(detected_map.keys())

        # 1. Recursive Implication Expansion
        while queue:
            current_tech = queue.pop(0)
            if current_tech in visited_implies:
                continue
            visited_implies.add(current_tech)

            rule = technology_rules.get(current_tech)
            if not rule or not rule.implies:
                continue

            for implied_name in rule.implies:
                if not implied_name or not isinstance(implied_name, str):
                    continue

                clean_implied = implied_name.split(r"\;")[0].strip()

                if clean_implied not in detected_map:
                    imp_rule = technology_rules.get(clean_implied)
                    categories = imp_rule.categories if imp_rule else ["Web Technology"]
                    cpes = imp_rule.cpes if imp_rule else []

                    detected_map[clean_implied] = {
                        "confidence": 80,
                        "version": None,
                        "category": categories[0] if categories else "Web Technology",
                        "cpes": cpes,
                        "evidence": [],
                        "inferred": True,
                        "inferred_from": current_tech
                    }
                    queue.append(clean_implied)

        # 2. Exclusion Rules Engine
        excluded_techs: Set[str] = set()
        for tech_name, tech_info in list(detected_map.items()):
            rule = technology_rules.get(tech_name)
            if rule and rule.excludes:
                for ex in rule.excludes:
                    if isinstance(ex, str) and ex.strip():
                        excluded_techs.add(ex.split(r"\;")[0].strip())

        # Enforce exclusions unless technology has strong direct evidence (confidence >= 90)
        for ex_tech in excluded_techs:
            if ex_tech in detected_map:
                entry = detected_map[ex_tech]
                if entry.get("inferred") or entry.get("confidence", 0) < 90:
                    logger.debug("Excluding technology '%s' due to exclusion rule.", ex_tech)
                    del detected_map[ex_tech]

        return detected_map
