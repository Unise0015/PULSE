import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class SvelteSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "svelte"

    @property
    def name(self) -> str:
        return "Svelte"

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
        # Svelte compiler generates unique CSS classes like class="svelte-1a2b3c" or svelte-xyz
        svelte_class_match = re.findall(r'class=["\'][^"\']*\bsvelte-([a-zA-Z0-9]{5,8})\b', html)
        if svelte_class_match:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value=f"svelte-{svelte_class_match[0]}",
                confidence=95,
                description=f"Svelte compiler CSS class svelte-{svelte_class_match[0]} found",
                reliability=EvidenceReliability.HIGH
            ))

        # 2. Scripts Checks
        svelte_pattern = r'svelte(?:@([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(svelte_pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"Svelte runtime script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        svelte_pattern = r'svelte(?:@|/)([\d\.]+)(?:\.min)?\.js'
        svelte_cdn_pattern = r'svelte(?:-([\d\.]+))?(?:\.min)?\.js'

        for script in scripts:
            match = re.search(svelte_pattern, script, re.IGNORECASE)
            if match:
                return match.group(1)
            match2 = re.search(svelte_cdn_pattern, script, re.IGNORECASE)
            if match2 and match2.group(1):
                return match2.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:svelte:svelte:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]
