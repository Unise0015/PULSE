import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class ReactSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "react"

    @property
    def name(self) -> str:
        return "React"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.UI_LIBRARY

    @property
    def priority(self) -> int:
        return 70

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def supports_relationships(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    @property
    def minimum_matches(self) -> int:
        return 2

    @property
    def parent_id(self) -> Optional[str]:
        return "nextjs"

    @property
    def ecosystem(self) -> Optional[str]:
        return "npm"

    @property
    def correlation_supported(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        # 1. HTML Checks
        if "data-reactroot" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="data-reactroot",
                confidence=95,
                description="React root node attribute data-reactroot present",
                reliability=EvidenceReliability.HIGH
            ))

        if "__REACT_DEVTOOLS_GLOBAL_HOOK__" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="__REACT_DEVTOOLS_GLOBAL_HOOK__",
                confidence=80,
                description="React DevTools hook initialization script present",
                reliability=EvidenceReliability.MEDIUM
            ))

        if "react.production.min.js" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="react.production.min.js",
                confidence=85,
                description="React production bundle filename referenced in HTML",
                reliability=EvidenceReliability.HIGH
            ))

        # 2. Scripts Checks
        react_pattern = r'react(?:@([\d\.]+))?(?:\.production)?(?:\.min)?\.js'
        react_dom_pattern = r'react-dom(?:-([\d\.]+))?(?:\.production)?(?:\.min)?\.js'
        
        for script in scripts:
            match = re.search(react_pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"React library script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))
            match_dom = re.search(react_dom_pattern, script, re.IGNORECASE)
            if match_dom:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"React DOM library script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        react_pattern = r'react(?:-dom)?(?:@|/)([\d\.]+)(?:\.production)?(?:\.min)?\.js'
        react_cdn_pattern = r'react(?:-dom)?(?:-([\d\.]+))?(?:\.production)?(?:\.min)?\.js'

        for script in scripts:
            match = re.search(react_pattern, script, re.IGNORECASE)
            if match:
                return match.group(1)
            match2 = re.search(react_cdn_pattern, script, re.IGNORECASE)
            if match2 and match2.group(1):
                return match2.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:facebook:react:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]
