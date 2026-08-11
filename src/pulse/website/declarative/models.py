"""
Data models for PULSE Declarative Web Technology Intelligence.
Defines PatternRule, TechnologyRule, DeclarativeEvidence, and normalized TechnologyFingerprint representations.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pulse.domain.models import (
    TechnologyFingerprint, CPECandidate, DetectionEvidence,
    DetectionMethod, DetectionStatus, ConfidenceBand, TechnologyCategory
)


@dataclass
class PatternRule:
    """Represents a single parsed detection pattern with modifiers."""
    raw_pattern: str
    regex: Optional[re.Pattern] = None
    version_group: Optional[str] = None
    confidence: int = 100

    def __post_init__(self):
        if self.regex is None and self.raw_pattern is not None:
            try:
                self.regex = re.compile(self.raw_pattern, re.IGNORECASE)
            except re.error:
                self.regex = None


@dataclass
class TechnologyRule:
    """Normalized technology signature definition."""
    name: str
    categories: List[str] = field(default_factory=list)
    headers: Dict[str, List[PatternRule]] = field(default_factory=dict)
    cookies: Dict[str, List[PatternRule]] = field(default_factory=dict)
    html: List[PatternRule] = field(default_factory=list)
    scripts: List[PatternRule] = field(default_factory=list)
    meta: Dict[str, List[PatternRule]] = field(default_factory=dict)
    url: List[PatternRule] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    implies: List[str] = field(default_factory=list)
    excludes: List[str] = field(default_factory=list)


@dataclass
class DeclarativeEvidence:
    """Explainable detection evidence record."""
    source: str           # header, cookie, html, script, meta
    matched_value: str
    pattern: str
    confidence: int
    header_name: Optional[str] = None
    cookie_name: Optional[str] = None
    meta_name: Optional[str] = None
    version: Optional[str] = None
    description: str = ""

    def to_domain_evidence(self) -> DetectionEvidence:
        """Converts DeclarativeEvidence to core PULSE DetectionEvidence model."""
        method_map = {
            "header": DetectionMethod.HEADER,
            "cookie": DetectionMethod.COOKIE,
            "html": DetectionMethod.HTML,
            "script": DetectionMethod.SCRIPT,
            "meta": DetectionMethod.META,
        }
        method = method_map.get(self.source.lower(), DetectionMethod.HEADER)
        desc = self.description or f"Matched pattern '{self.pattern}' in {self.source}"
        if self.header_name:
            desc = f"Matched header '{self.header_name}' pattern '{self.pattern}'"
        elif self.cookie_name:
            desc = f"Matched cookie '{self.cookie_name}' pattern '{self.pattern}'"
        elif self.meta_name:
            desc = f"Matched meta generator '{self.meta_name}' pattern '{self.pattern}'"

        return DetectionEvidence(
            method=method,
            source=self.source,
            value=self.matched_value,
            confidence=self.confidence,
            description=desc
        )
