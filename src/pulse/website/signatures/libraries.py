import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class JQuerySignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "jquery"

    @property
    def name(self) -> str:
        return "jquery"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.UI_LIBRARY

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
        pattern = r'jquery(?:-([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"jQuery library script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))
        if "jQuery" in html or "$(" in html:
            # Low confidence generic indicator
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="jQuery / $() usage",
                confidence=40,
                description="Potential jQuery usage signatures in HTML content",
                reliability=EvidenceReliability.LOW
            ))
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        pattern = r'jquery(?:-([\d\.]+))?(?:\.min)?\.js'
        pattern_url = r'jquery/([\d\.]+)/jquery'
        for script in scripts:
            match = re.search(pattern, script, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1)
            match_url = re.search(pattern_url, script, re.IGNORECASE)
            if match_url:
                return match_url.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:jquery:jquery:{ver}:*:*:*:*:*:*:*", confidence=95)]


class BootstrapSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "bootstrap"

    @property
    def name(self) -> str:
        return "bootstrap"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.UI_LIBRARY

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
        pattern = r'bootstrap(?:@([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"Bootstrap javascript library script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))
        if "bootstrap.min.css" in html or "bootstrap.css" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Link",
                value="bootstrap stylesheet",
                confidence=85,
                description="Bootstrap CSS stylesheet link detected",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        pattern = r'bootstrap(?:@|/)([\d\.]+)(?:\.min)?(?:\.js|\.css)'
        pattern_dash = r'bootstrap-([\d\.]+)(?:\.min)?(?:\.js|\.css)'
        for script in scripts:
            match = re.search(pattern, script, re.IGNORECASE)
            if match:
                return match.group(1)
        # Check stylesheet links in HTML
        match_css = re.search(pattern, html, re.IGNORECASE)
        if match_css:
            return match_css.group(1)
        match_dash = re.search(pattern_dash, html, re.IGNORECASE)
        if match_dash:
            return match_dash.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:getbootstrap:bootstrap:{ver}:*:*:*:*:*:*:*", confidence=95)]


class TailwindSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "tailwind"

    @property
    def name(self) -> str:
        return "tailwind"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.UI_LIBRARY

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
        pattern = r'tailwind(?:css)?(?:@([\d\.]+))?(?:\.min)?\.js'
        for script in scripts:
            match = re.search(pattern, script, re.IGNORECASE)
            if match:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=85,
                    description=f"Tailwind CSS client script referenced: {script}",
                    reliability=EvidenceReliability.HIGH
                ))
        if "tailwindcss" in html or "tailwind.config" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Content",
                value="tailwind reference",
                confidence=60,
                description="Tailwind CSS reference detected in page content",
                reliability=EvidenceReliability.MEDIUM
            ))
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        pattern = r'tailwind(?:css)?@([\d\.]+)(?:\.min)?\.js'
        for script in scripts:
            match = re.search(pattern, script, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:tailwindcss:tailwindcss:{ver}:*:*:*:*:*:*:*", confidence=95)]
