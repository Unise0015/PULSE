import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class VueSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "vue"

    @property
    def name(self) -> str:
        return "Vue.js"

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
    def supports_relationships(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    @property
    def parent_id(self) -> Optional[str]:
        return "nuxtjs"

    @property
    def ecosystem(self) -> Optional[str]:
        return "npm"

    @property
    def correlation_supported(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        # 1. HTML Checks
        # Vue attributes: v-cloak, v-bind, data-v-, Vue specific comments or roots
        if "v-cloak" in html or "v-bind" in html or "data-v-" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="data-v- / v-cloak",
                confidence=90,
                description="Vue template directives or scope attributes found",
                reliability=EvidenceReliability.HIGH
            ))

        if "vue.runtime" in html or "vue.js" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="vue.js",
                confidence=85,
                description="Vue library referenced in HTML",
                reliability=EvidenceReliability.HIGH
            ))

        # 2. Scripts Checks
        vue_pattern = r'vue(?:@([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(vue_pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"Vue framework script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        vue_pattern = r'vue(?:@|/)([\d\.]+)(?:\.min)?\.js'
        vue_cdn_pattern = r'vue(?:-([\d\.]+))?(?:\.min)?\.js'

        for script in scripts:
            match = re.search(vue_pattern, script, re.IGNORECASE)
            if match:
                return match.group(1)
            match2 = re.search(vue_cdn_pattern, script, re.IGNORECASE)
            if match2 and match2.group(1):
                return match2.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:vuejs:vue.js:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]
