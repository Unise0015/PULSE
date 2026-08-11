"""
Signature Index for PULSE Declarative Web Technology Intelligence.
Provides O(1) header, cookie, meta, script, and HTML pre-filtering lookup tables.
"""

from typing import Dict, List, Tuple
from pulse.website.declarative.models import PatternRule, TechnologyRule


class SignatureIndex:
    """Index structure to avoid evaluating all signature rules against every response."""

    def __init__(self, technology_rules: Dict[str, TechnologyRule]):
        self.headers: Dict[str, List[Tuple[str, PatternRule]]] = {}      # lowercase_header_name -> [(tech_name, rule)]
        self.cookies: Dict[str, List[Tuple[str, PatternRule]]] = {}      # lowercase_cookie_name -> [(tech_name, rule)]
        self.meta: Dict[str, List[Tuple[str, PatternRule]]] = {}        # lowercase_meta_name -> [(tech_name, rule)]
        self.script_src_rules: List[Tuple[str, PatternRule]] = []       # [(tech_name, rule)]
        self.html_rules: List[Tuple[str, PatternRule]] = []             # [(tech_name, rule)]
        self.url_rules: List[Tuple[str, PatternRule]] = []              # [(tech_name, rule)]

        self.build_index(technology_rules)

    def build_index(self, technology_rules: Dict[str, TechnologyRule]):
        """Populates pre-filtered index lookup tables from loaded technology rules."""
        for tech_name, rule in technology_rules.items():
            # Headers
            for h_name, pat_rules in rule.headers.items():
                h_key = h_name.lower().strip()
                for pr in pat_rules:
                    self.headers.setdefault(h_key, []).append((tech_name, pr))

            # Cookies
            for c_name, pat_rules in rule.cookies.items():
                c_key = c_name.lower().strip()
                for pr in pat_rules:
                    self.cookies.setdefault(c_key, []).append((tech_name, pr))

            # Meta
            for m_name, pat_rules in rule.meta.items():
                m_key = m_name.lower().strip()
                for pr in pat_rules:
                    self.meta.setdefault(m_key, []).append((tech_name, pr))

            # Scripts
            for pr in rule.scripts:
                self.script_src_rules.append((tech_name, pr))

            # HTML
            for pr in rule.html:
                self.html_rules.append((tech_name, pr))

            # URL
            for pr in rule.url:
                self.url_rules.append((tech_name, pr))
