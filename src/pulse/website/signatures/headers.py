import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class NginxSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "nginx"

    @property
    def name(self) -> str:
        return "nginx"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.SERVER

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "")
        if "nginx" in server.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value=server,
                confidence=95,
                description="Nginx server banner present",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        server = headers.get("Server", "")
        match = re.search(r'nginx/([\d\.]+)', server, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:f5:nginx:{ver}:*:*:*:*:*:*:*", confidence=95)]


class ApacheSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "apache"

    @property
    def name(self) -> str:
        return "apache"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.SERVER

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "")
        if "apache" in server.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value=server,
                confidence=95,
                description="Apache server banner present",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        server = headers.get("Server", "")
        match = re.search(r'apache/([\d\.]+)', server, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:apache:http_server:{ver}:*:*:*:*:*:*:*", confidence=95)]


class MicrosoftIisSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "iis"

    @property
    def name(self) -> str:
        return "iis"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.SERVER

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "")
        if "microsoft-iis" in server.lower() or server.lower() == "iis":
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value=server,
                confidence=95,
                description="Microsoft IIS server banner present",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        server = headers.get("Server", "")
        match = re.search(r'microsoft-iis/([\d\.]+)', server, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:microsoft:iis:{ver}:*:*:*:*:*:*:*", confidence=95)]


class ReverseProxySignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "proxy"

    @property
    def name(self) -> str:
        return "proxy"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.PROXY

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        via = headers.get("Via", "")
        if via:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Via",
                value=via,
                confidence=50,
                description="Reverse proxy detected via Via header",
                reliability=EvidenceReliability.MEDIUM
            ))
        return evidence
