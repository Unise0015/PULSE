import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class AngularSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "angular"

    @property
    def name(self) -> str:
        return "Angular"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.FRAMEWORK

    @property
    def priority(self) -> int:
        return 80

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    @property
    def ecosystem(self) -> Optional[str]:
        return "npm"

    @property
    def correlation_supported(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        # 1. HTML Checks
        if "ng-version" in html:
            # Extract ng-version if present to report as value
            match = re.search(r'ng-version=["\']([^"\']+)["\']', html)
            val = match.group(0) if match else "ng-version"
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value=val,
                confidence=95,
                description="Angular application attribute ng-version present",
                reliability=EvidenceReliability.VERIFIED
            ))

        if "ng-app" in html or "ng-controller" in html or "ng-binding" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="ng-app / ng-controller",
                confidence=90,
                description="AngularJS attributes (ng-app/ng-controller) present",
                reliability=EvidenceReliability.HIGH
            ))

        # 2. Scripts Checks
        angular_pattern = r'angular(?:-([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(angular_pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"Angular framework script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        # Try meta/attribute extraction
        match = re.search(r'ng-version=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)

        # Try script extraction
        angular_pattern = r'angular(?:-([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(angular_pattern, script, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:angular:angular:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]
