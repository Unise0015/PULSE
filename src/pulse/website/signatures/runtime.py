import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class PhpRuntimeSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "php"

    @property
    def name(self) -> str:
        return "php"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.RUNTIME

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        
        x_powered_by = headers.get("X-Powered-By", "")
        if "php" in x_powered_by.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-Powered-By",
                value=x_powered_by,
                confidence=95,
                description="PHP runtime detected via X-Powered-By header",
                reliability=EvidenceReliability.HIGH
            ))
            
        server = headers.get("Server", "")
        if "php" in server.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value=server,
                confidence=90,
                description="PHP detected in Server header",
                reliability=EvidenceReliability.HIGH
            ))
            
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        x_powered_by = headers.get("X-Powered-By", "")
        match = re.search(r'php/([\d\.]+)', x_powered_by, re.IGNORECASE)
        if match:
            return match.group(1)
            
        server = headers.get("Server", "")
        match = re.search(r'php/([\d\.]+)', server, re.IGNORECASE)
        if match:
            return match.group(1)
            
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:php:php:{ver}:*:*:*:*:*:*:*", confidence=95)]


class NodeJsRuntimeSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "nodejs"

    @property
    def name(self) -> str:
        return "node.js"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.RUNTIME

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        
        x_powered_by = headers.get("X-Powered-By", "")
        if "node" in x_powered_by.lower() or "express" in x_powered_by.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-Powered-By",
                value=x_powered_by,
                confidence=90,
                description="Node.js/Express detected via X-Powered-By header",
                reliability=EvidenceReliability.HIGH
            ))
            
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        x_powered_by = headers.get("X-Powered-By", "")
        match = re.search(r'node\.js/([\d\.]+)', x_powered_by, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:nodejs:node.js:{ver}:*:*:*:*:*:*:*", confidence=95)]


class PythonRuntimeSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "python"

    @property
    def name(self) -> str:
        return "python"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.RUNTIME

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        
        x_powered_by = headers.get("X-Powered-By", "")
        if "python" in x_powered_by.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-Powered-By",
                value=x_powered_by,
                confidence=95,
                description="Python runtime detected via X-Powered-By header",
                reliability=EvidenceReliability.HIGH
            ))
            
        server = headers.get("Server", "")
        if "python" in server.lower() or "cpython" in server.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value=server,
                confidence=90,
                description="Python/CPython detected in Server header",
                reliability=EvidenceReliability.HIGH
            ))
            
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        x_powered_by = headers.get("X-Powered-By", "")
        match = re.search(r'python/([\d\.]+)', x_powered_by, re.IGNORECASE)
        if match:
            return match.group(1)
            
        server = headers.get("Server", "")
        match = re.search(r'(?:python|cpython)/([\d\.]+)', server, re.IGNORECASE)
        if match:
            return match.group(1)
            
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:python:python:{ver}:*:*:*:*:*:*:*", confidence=95)]


class AspNetFrameworkSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "aspnet"

    @property
    def name(self) -> str:
        return "asp.net"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.FRAMEWORK

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        
        x_powered_by = headers.get("X-Powered-By", "")
        if "asp.net" in x_powered_by.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-Powered-By",
                value=x_powered_by,
                confidence=90,
                description="ASP.NET detected via X-Powered-By header",
                reliability=EvidenceReliability.HIGH
            ))
            
        asp_version = headers.get("X-AspNet-Version", "")
        if asp_version:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-AspNet-Version",
                value=asp_version,
                confidence=95,
                description=f"ASP.NET framework version detected via X-AspNet-Version: {asp_version}",
                reliability=EvidenceReliability.VERIFIED
            ))
            
        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        asp_version = headers.get("X-AspNet-Version", "")
        if asp_version:
            return asp_version
            
        x_powered_by = headers.get("X-Powered-By", "")
        match = re.search(r'asp\.net/([\d\.]+)', x_powered_by, re.IGNORECASE)
        if match:
            return match.group(1)
            
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:microsoft:asp.net:{ver}:*:*:*:*:*:*:*", confidence=95)]
