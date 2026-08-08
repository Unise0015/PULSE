import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class WordPressSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "wordpress"

    @property
    def name(self) -> str:
        return "WordPress"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CMS

    @property
    def priority(self) -> int:
        return 60

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        # 1. Generator tag check
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([^"\']*)["\']', html, re.IGNORECASE)
        if match:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.META,
                source="Generator Meta Tag",
                value=match.group(0),
                confidence=95,
                description="WordPress generator meta tag present",
                reliability=EvidenceReliability.VERIFIED
            ))

        # 2. Path checks
        if "wp-content/" in html or "wp-includes/" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body Paths",
                value="wp-content / wp-includes",
                confidence=90,
                description="WordPress wp-content or wp-includes paths found in HTML",
                reliability=EvidenceReliability.HIGH
            ))

        # 3. Cookies check
        wordpress_cookies = [c for c in cookies if c.startswith("wordpress_") or c.startswith("wp-settings-")]
        if wordpress_cookies:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value=f"Matched cookies: {wordpress_cookies}",
                confidence=95,
                description="WordPress login or settings cookie detected",
                reliability=EvidenceReliability.HIGH
            ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d\.]+)["\']', html, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:wordpress:wordpress:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]


class DrupalSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "drupal"

    @property
    def name(self) -> str:
        return "Drupal"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CMS

    @property
    def priority(self) -> int:
        return 60

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([^"\']*)["\']', html, re.IGNORECASE)
        if match:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.META,
                source="Generator Meta Tag",
                value=match.group(0),
                confidence=95,
                description="Drupal generator meta tag present",
                reliability=EvidenceReliability.VERIFIED
            ))

        if "sites/default/files/" in html or "sites/all/" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body Paths",
                value="sites/default/files",
                confidence=90,
                description="Drupal assets folder path found in HTML",
                reliability=EvidenceReliability.HIGH
            ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d\.]+)["\']', html, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:drupal:drupal:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]


class JoomlaSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "joomla"

    @property
    def name(self) -> str:
        return "Joomla"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CMS

    @property
    def priority(self) -> int:
        return 60

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla\s*([^"\']*)["\']', html, re.IGNORECASE)
        if match:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.META,
                source="Generator Meta Tag",
                value=match.group(0),
                confidence=95,
                description="Joomla generator meta tag present",
                reliability=EvidenceReliability.VERIFIED
            ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla\s*([\d\.]+)["\']', html, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:joomla:joomla:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]
