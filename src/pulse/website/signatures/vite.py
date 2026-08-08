import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class ViteSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "vite"

    @property
    def name(self) -> str:
        return "Vite"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.BUILD_TOOL

    @property
    def priority(self) -> int:
        return 70

    @property
    def provides_version(self) -> bool:
        return False

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
        if "/@vite/client" in html or "__vite_plugin_react_preamble_installed__" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="/@vite/client",
                confidence=95,
                description="Vite dev server client script or React preamble detected",
                reliability=EvidenceReliability.VERIFIED
            ))

        # 2. Scripts Checks
        for script in scripts:
            if "/@vite/client" in script or "/@id/__x00__" in script:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=95,
                    description="Vite development client hot-reload script loaded",
                    reliability=EvidenceReliability.VERIFIED
                ))

        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        return [
            CPECandidate(cpe="cpe:2.3:a:vitejs:vite:*:*:*:*:*:*:*:*", confidence=95)
        ]
